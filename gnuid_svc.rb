require 'sinatra'
require 'sinatra/cookies'
require 'json'
require 'base64'
require 'date'
require 'net/http'
require 'json'

enable :sessions

set :bind, '0.0.0.0'

requiredInfo = [ "email", "name" ]

knownUserKeys = Array.new

$knownIdentities = {}
$passwords = {}
$codes = {}
$nonces = {}
$tokens = {}

`update-ca-certificates`
$demo_pkey = JSON.parse(`curl -s --socks5-hostname '#{ENV['RECLAIM_RUNTIME']}':7777 https://api.reclaim/identity/name/reclaim`)["pubkey"]

$reclaimEndpoint = ARGV[0]

def exchange_code_for_token(id_ticket, expected_nonce)
  p "Expected nonce: "+expected_nonce.to_s
  resp = `curl -X POST --socks5-hostname '#{ENV['RECLAIM_RUNTIME']}':7777 '#{ENV['RECLAIM_RUNTIME']}/openid/token?grant_type=authorization_code&redirect_uri=https://demo.'#{$demo_pkey}'/login&code=#{id_ticket}' -u '#{$demo_pkey}':secret -k`
  p resp
  json = JSON.parse(resp)
  p json
  return nil if json.nil? or json.empty?
  id_token = json["id_token"]
  access_token = json["access_token"]
  resp = `curl -X POST --socks5-hostname '#{$RECLAIM_RUNTIME}':7777 '#{$reclaimEndpoint}/openid/userinfo' -H 'Authorization: Bearer #{access_token}' -k`
  p resp

  return nil if id_token.nil?
  header_b64 = id_token.split(".")[0]
  payload_b64 = id_token.split(".")[1]
  signature = id_token.split(".")[2]
  plain = Base64.decode64(payload_b64)
  payload_userinfo = JSON.parse(resp)
  payload = JSON.parse(plain)
  #return nil unless expected_nonce == payload["nonce"].to_i
  identity = payload["iss"]
  p payload
  p payload_userinfo
  $knownIdentities[identity] = payload_userinfo
  $tokens[identity] = id_token
  $codes[identity] = id_ticket
  return identity
end

def is_token_expired (token)
  return true # TODO if token.nil?
  identity = $knownIdentities[token["iss"]]
  exp = Time.at(token["exp"] / 1000000)
  if (Time.now > exp)
    # Get new token
    new_token = `gnunet-gns -u #{$codes[identity]}.gnu -p #{token["iss"]} -t ID_TOKEN --raw -T 5000`
    if (new_token.nil? or new_token.empty?)
      $knownIdentities[token["iss"]] = nil
      return true
    end
    new_token = JSON.parse(new_token)
    exp = Time.at(new_token["exp"] / 1000000)
    if (Time.now > exp)
      $knownIdentities[token["iss"]] = nil
      return true
    else
      $knownIdentities[token["iss"]] = new_token
      return false
    end
  else
    # Check if token revoked
    return false
  end
end

get '/logout' do
  if (!session["user"].nil?)
    session["user"] = nil
    redirect to('/login')
  end
  return "Not logged in"
end

def getUser(identity)
  return nil if identity.nil? or $knownIdentities[identity].nil?
  return $knownIdentities[identity]["full_name"] unless $knownIdentities[identity]["full_name"].nil?
  return $knownIdentities[identity]["sub"]
end

get '/' do
  identity = session["user"]

  if (!identity.nil?)
    token = $knownIdentities[identity]
    #if (is_token_expired (token))
    #  # Token is expired
    #  redirect "/login"
    #end
    if (!token.nil?)
      email = token["email"]
      #msg = "Welcome back #{$knownIdentities[identity]["sub"]}"
      #msg += "<br/> Your phone number is: #{phone}"
      #exp = token["exp"] / 1000000
      #msg += "<br/>Your token will expire at: #{Time.at(exp).to_s}"
      return haml :info, :locals => {
        :user => getUser(identity),
        :title => "Welcome.",
        :subtitle => "Welcome back #{$knownIdentities[identity]["full_name"]} (#{email})",
        :content => "Login successful! (OpenID Token: #{$tokens[identity]})"}
    end
  end

  redirect "/login"
end

get "/login" do
  identity = session["user"]
  token = params[:id_token]
  id_ticket = params[:code]

  # Identity parameter takes precendence over cookie
  #if (!params[:identity].nil?)
  #  identity = params[:identity]
  #end

  if (!identity.nil?)
    token = $knownIdentities[identity]
    p token
    #if ($passwords[identity].nil?)
    #  # New user -> register
    #  redirect "/register?identity="+identity
    #  return
    #end

    #if (is_token_expired (token))
      # Token is expired
    #  p "Token expired!"
    #end

    if (!token.nil?)
      redirect "/"
    end

  end

  if (!id_ticket.nil?)
    identity = exchange_code_for_token(id_ticket, $nonces[session["id"]])
    p "Deleting nonce"
    $nonces[session["id"]] = nil
    if (identity.nil?)
      return "Error!"
    end
    token = $knownIdentities[identity]
    p token
    email = $knownIdentities[identity]["email"]
    session["user"] = identity
    if (email.nil?)
        return "You did not provide a valid email. Please grant us access to your email!<br/> <a href=https://ui.reclaim/#/identities/#{identity}?requested_by=http%3A//demo.reclaim/&requested_attrs=phone>Grant access</a>"
    end
    #Handle token contents
    redirect "/"
  elsif (identity.nil?)
    nonce = rand(100000)
    session["id"] = rand(100000)
    $nonces[session["id"]] = nonce
    return haml :login, :locals => {
      :user => getUser(nil),
      :title => "Login",
      :nonce => nonce,
      :reclaimEndpoint => $reclaimEndpoint,
      :demo_pkey => $demo_pkey
    }
    #elsif (oauth_code.nil?)
    #  haml :grant, :locals => {:user => getUser(identity), :haml_id => identity, :title => "Information Needed"}
    #elsif (!identity.nil? and !grant_lbl.nil?)
    #  $knownIdentities[identity] = grant_lbl
  end
end
