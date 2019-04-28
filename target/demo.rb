require 'sinatra'
require 'sinatra/cookies'
require 'json'
require 'base64'
require 'date'
require 'net/http'
require 'json'
require 'jwt'
require 'cgi'
require 'socksify'
require 'socksify/http'

enable :sessions

set :bind, '0.0.0.0'
set :show_exceptions, false
Socksify::debug = true

requiredInfo = [ "email", "name" ]

knownUserKeys = Array.new

$knownIdentities = {}
$passwords = {}
$codes = {}
$nonces = {}
$tokens = {}
$reclaim_endpoint = ARGV[0]
$token_endpoint = "#{$reclaim_endpoint}/openid/token"
$userinfo_endpoint = "#{$reclaim_endpoint}/openid/userinfo"

if ENV['RECLAIM_RUNTIME'].nil?
  $reclaim_runtime = '127.0.0.1'
else
  $reclaim_runtime = ENV['RECLAIM_RUNTIME']
end

if ENV["PSW_SECRET"].nil?
  $client_secret = 'secret'
else
  $client_secret = ENV["PSW_SECRET"]
end


#$demo_pkey = JSON.parse(`curl --socks5-hostname '#{ENV['RECLAIM_RUNTIME']}':7777 https://api.reclaim/identity/name/reclaim`)["pubkey"]
begin
  uri = URI.parse("#{$reclaim_endpoint}/identity/name/reclaim")
  req = Net::HTTP::Get.new(uri)
  Net::HTTP.SOCKSProxy($reclaim_runtime, 7777).start(uri.host, uri.port, :use_ssl => true,
                                                     :verify_mode => OpenSSL::SSL::VERIFY_NONE) do |http|
    resp = http.request(req).body
    puts resp
    $demo_pkey = JSON.parse(resp)["pubkey"]
  end
rescue Exception => e
  puts "ERROR: Failed to get my pubkey! (#{e.message})"
  puts e.backtrace
  exit
end

p $demo_pkey

def oidc_token_request(authz_code)
  puts "Executing OpenID Token request"
  begin
    uri = URI.parse("#{$token_endpoint}?grant_type=authorization_code&redirect_uri=https://demo.#{$demo_pkey}/login&code=#{CGI.escape(authz_code)}")
    req = Net::HTTP::Post.new(uri)
    req.basic_auth $demo_pkey, $client_secret
    Net::HTTP.SOCKSProxy($reclaim_runtime, 7777).start(uri.host, uri.port, :use_ssl => true,
                                                       :verify_mode => OpenSSL::SSL::VERIFY_NONE) do |http|
      return http.request(req).body
    end
  rescue Exception => e
    puts "ERROR: Token request failed! (#{e.message})"
    puts e.backtrace
    return nil
  end
end

def parse_token_response(response)
  begin
    json = JSON.parse(response)
  rescue JSON::ParserError
    puts "ERROR: Unable to parse JSON"
    return nil
  end
  raise "JSON is empty" if json.nil? or json.empty?
  id_jwt = json["id_token"]
  raise "No ID Token" if id_jwt.nil?
  access_token = json["access_token"]
  begin
    #                      JWT     pwd  validation (have no key)
    id_token = JWT.decode(id_jwt, $client_secret, true,  {algorithm: 'HS512' })
    payload = id_jwt[0] # 0 is payload, 1 is header
  rescue
    puts "ERROR: Unable to decode JWT"
    return nil
  end
  return {:access_token => access_token, :id_token => id_token}
end

def exchange_code_for_token(code, expected_nonce)
  #cmd = "curl -X POST --socks5-hostname #{ENV['RECLAIM_RUNTIME']}:7777 'https://api.reclaim/openid/token?grant_type=authorization_code&redirect_uri=https://demo.#{$demo_pkey}/login&code=#{CGI.escape(id_ticket)}' -u #{$demo_pkey}:#{ENV["PSW_SECRET"]}"
  #p "Executing: "+cmd

  #resp = `#{cmd}`
  resp = oidc_token_request(code)
  puts resp

  tokens = parse_token_response(resp)
  raise "ERROR: unable to parse tokens!" if tokens.nil?
  payload = tokens[:id_token][0] # 0 is payload, 1 is header
  identity = payload["iss"]
  $knownIdentities[identity] = payload

  #Async retrieval of userinfo
  Thread.new do
    #resp = `curl -X POST --socks5-hostname '#{ENV['RECLAIM_RUNTIME']}':7777 'https://api.reclaim/openid/userinfo' -H 'Authorization: Bearer #{access_token}'`
    begin
      puts "Getting Userinfo..."
      uri = URI.parse($userinfo_endpoint)
      req = Net::HTTP::Post.new(uri)
      req['Authorization'] = "Bearer #{tokens[:access_token]}"
      Net::HTTP.SOCKSProxy($reclaim_runtime, 7777).start(uri.host, uri.port, :use_ssl => true,
                                                         :verify_mode => OpenSSL::SSL::VERIFY_NONE) do |http|
        resp = http.request(req)
        puts resp
        $knownIdentities[identity] = JSON.parse(resp)
        puts "Userinfo: #{$knownIdentities[identity]}"
      end
    rescue JSON::ParserError
      puts "ERROR: Unable to retrieve Userinfo! Using ID Token contents..."
    rescue
      puts "ERROR: Userinfo request failed!"
    end
  end
  raise "Expected nonce #{expected_nonce} != #{payload["nonce"].to_i}" if expected_nonce != payload["nonce"].to_i

  $tokens[identity] = tokens[:id_token]
  $codes[identity] = code
  return identity
end


def logout()
  session["user"] = nil
end

get '/logout' do
  logout()
  redirect to('/login')
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
    if (!token.nil?)
      email = token["email"]
      return haml :info, :locals => {
        :user => getUser(identity),
        :title => "Welcome.",
        :subtitle => "Welcome back #{$knownIdentities[identity]["full_name"]} (#{email})",
        :content => ""}
    end
  end

  redirect "/login"
end

get "/access_denied" do
  return haml :access_denied, :locals => {
    :user => getUser(nil),
    :title => "Error",
    :subtitle => "Access was denied",
    :content => "You have chosen to deny access to share your identity with us.<br \>
        You can try again by clicking the button below.<br \>
        (The chosen identity provider supplied the following error decription: #{params["error_description"]})"}
end

get "/login" do
  identity = session["user"]
  token = params[:id_token]
  id_ticket = params[:code]

  if(params["error"] == 'access_denied')
    redirect "/access_denied?error_description=#{params["error_description"]}"
  else
    if (params["error"] != nil)
      p params["error"]
      p "ERROR! unhandled/unexpected error occurred"
      redirect "/"
    end
  end

  if (!identity.nil?)
    token = $knownIdentities[identity]
    p token

    if (!token.nil?)
      redirect "/"
    end

  end

  if (!id_ticket.nil?)
    begin
      identity = exchange_code_for_token(id_ticket, $nonces[session["id"]])
      $nonces[session["id"]] = nil
      token = $knownIdentities[identity]
      email = $knownIdentities[identity]["email"]
      session["user"] = identity
      if (email.nil?)
        #return "You did not provide a valid email. Please grant us access to your email!<br/> <a href=https://ui.reclaim/#/identities/#{identity}?requested_by=http%3A//demo.reclaim/&requested_attrs=phone>Grant access</a>"
        logout()
        return haml :login, :locals => {
          :user => getUser(nil),
          :title => "Login",
          :subtitle => "You did not provide a valid email. Please grant us access to your email!",
          :nonce => nonce,
          :reclaim_endpoint => $reclaim_endpoint,
          :demo_pkey => $demo_pkey
        }
      end
      #Handle token contents
      redirect "/"
    rescue Exception => e
      puts e.message
      puts e.backtrace.inspect
      return CGI.escapeHTML(e.message)
    end
  elsif (identity.nil?)
    nonce = rand(100000)
    session["id"] = rand(100000)
    $nonces[session["id"]] = nonce
    return haml :login, :locals => {
      :user => getUser(nil),
      :title => "Login",
      :subtitle => "To use the re:claim messaging board, you must first authenticate yourself!",
      :nonce => nonce,
      :reclaim_endpoint => $reclaim_endpoint,
      :demo_pkey => $demo_pkey
    }
  end
end

get "/submit" do
  identity = session["user"]

  if (!identity.nil?)
    token = $knownIdentities[identity]
    if (!token.nil?)
      email = token["email"]
      begin
        file = File.open("guestbook.txt", "a")
        file.write("<tr><td><a href=\"mailto:"+email+"\">"+$knownIdentities[identity]["full_name"]+"</a></td><td>"+params["message"]+"</td></tr>")
      rescue IOError => e
      ensure
        file.close unless file.nil?
      end
      redirect("/")
    end
  end

end


# catch-all error handler
# redirect back to main page (login) in case of errors
error do
  redirect("/")
end
