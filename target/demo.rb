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
require 'securerandom'
require 'digest'

require './config.rb'

enable :sessions

set :bind, '0.0.0.0'
set :show_exceptions, true
Socksify::debug = true

config = DemoConfig::load()
$reclaim_rest_endpoint = config['system']['runtime']
$reclaim_rest_endpoint = "https://api.reclaim" unless ENV['RECLAIM_USE_PROXY'].nil?

#OpenID Endpoints
$use_proxy = !ENV['RECLAIM_USE_PROXY'].nil?
$token_endpoint = "#{$reclaim_rest_endpoint}/openid/token"
$userinfo_endpoint = "#{$reclaim_rest_endpoint}/openid/userinfo"

#DO NOT CHANGE!
$authorization_endpoint = "https://api.reclaim/openid/authorize"

#OpenID Parameters
$client_id = config['openid']['client_id']
$redirect_uri= config['openid']['redirect_uri']
$client_secret = config['openid']['client_secret']
$jwt_secret = config['openid']['jwt_secret']
$myhost = config['system']['host']

#re:claimID info

#The runtime IP is usually correct like this unless you run in a virtual
#environment (e.g. docker)
$gns_proxy = '127.0.0.1'
$gns_proxy = ENV['RECLAIM_RUNTIME'] unless ENV['RECLAIM_RUNTIME'].nil?
$client_secret = ENV["PSW_SECRET"] unless ENV["PSW_SECRET"].nil?
$jwt_secret = ENV["JWT_SECRET"] unless ENV["JWT_SECRET"].nil?

# Global program variables
$knownIdentities = {}
$passwords = {}
$codes = {}
$nonces = {}
$code_verifier = {}
$tokens = {}
$defaultMessages = [{:senderEmail => "john@doe.com", :senderName => "John Doe", :message => "Hello World!"}]
$messages = {}

def http_request_proxy(req, uri)
  Net::HTTP.SOCKSProxy($gns_proxy, 7777).start(uri.host, uri.port, :use_ssl => true,
                                                     :verify_mode => OpenSSL::SSL::VERIFY_NONE) do |http|
    resp = http.request(req).body
    p resp
    return resp
  end
end

def http_request(req, uri)
  return http_request_proxy(req, uri) if $use_proxy
  Net::HTTP.start(uri.host, uri.port) do |http|
    resp = http.request(req).body
    p resp
    return resp
  end
end

def http_get(url)
  uri = URI.parse(url)
  req = Net::HTTP::Get.new(uri)
  return http_request(req,uri)
end

#This is only used for our demo automation
if not ENV["CLIENT_NAME"].nil?
  begin
    resp = http_get("#{$reclaim_rest_endpoint}/identity/name/#{ENV["CLIENT_NAME"]}")
    $client_id = JSON.parse(resp)["pubkey"]
    $redirect_uri="https://demo.#{$client_id}/login"
  rescue Exception => e
    puts "ERROR: Failed to get my pubkey! (#{e.message})"
    puts e.backtrace
    exit
  end
end

def getFhgUid(identity)
  return "" if identity.nil? or $knownIdentities[identity].nil? or $knownIdentities[identity]["_claim_names"].nil? or $knownIdentities[identity]["_claim_sources"].nil?
  $knownIdentities[identity]["_claim_names"] = JSON.parse($knownIdentities[identity]["_claim_names"])
  $knownIdentities[identity]["_claim_sources"] = JSON.parse($knownIdentities[identity]["_claim_sources"])
  return "" if $knownIdentities[identity]["_claim_names"]["fhguid"].nil?
  attest_name = $knownIdentities[identity]["_claim_names"]["fhguid"]
  return "" if $knownIdentities[identity]["_claim_sources"][attest_name].nil?
  $knownIdentities[identity]["_claim_sources"][attest_name] = JSON.parse($knownIdentities[identity]["_claim_sources"][attest_name])
  jwt = $knownIdentities[identity]["_claim_sources"][attest_name]["JWT"]
  return "" if jwt.nil?
  #Manually split for now TODO correctly verify JWT
  payload_json = jwt.split(".")[1]
  return "" if payload_json.nil?
  begin
    payload = JSON.parse(Base64.decode64(payload_json))
  rescue
    return ""
  end
  return "" if payload.nil?
  return "FhG account: #{CGI.escapeHTML(payload["fhguid"])}"
end

def oidc_token_request(authz_code, code_verifier)
  puts "Executing OpenID Token request"
  begin
    uri = URI.parse("#{$token_endpoint}?grant_type=authorization_code&redirect_uri=#{$redirect_uri}&code=#{CGI.escape(authz_code)}&code_verifier=#{code_verifier}")
    req = Net::HTTP::Post.new(uri)
    req.basic_auth $client_id, $client_secret
    return http_request(req,uri)
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
    p "ERROR: Unable to parse JSON"
    return nil
  end
  raise "JSON is empty" if json.nil? or json.empty?
  id_jwt = json["id_token"]
  raise "No ID Token" if id_jwt.nil?
  access_token = json["access_token"]
  begin
    #                      JWT     pwd  validation (have no key)
    id_token = JWT.decode(id_jwt, $jwt_secret, true,  {algorithm: 'HS512' })
    payload = id_token[0] # 0 is payload, 1 is header
  rescue Exception => e
    p "ERROR: Unable to decode JWT: " + e.message
    return nil
  end
  return {:access_token => access_token, :id_token => id_token}
end

def exchange_code_for_token(code, expected_nonce, code_verifier)
  resp = oidc_token_request(code, code_verifier)
  p resp

  tokens = parse_token_response(resp)
  raise "ERROR: unable to parse tokens!" if tokens.nil?
  payload = tokens[:id_token][0] # 0 is payload, 1 is header
  identity = payload["sub"]
  $knownIdentities[identity] = payload

  #Async retrieval of userinfo
  Thread.new do
    begin
      puts "Getting Userinfo..."
      uri = URI.parse($userinfo_endpoint)
      req = Net::HTTP::Post.new(uri)
      req['Authorization'] = "Bearer #{tokens[:access_token]}"
      resp = http_request(req,uri)
      p resp
      $knownIdentities[identity] = JSON.parse(resp)
      p "Userinfo: #{$knownIdentities[identity]}"
    rescue JSON::ParserError
      p "ERROR: Unable to retrieve Userinfo! Using ID Token contents..."
    rescue Exception => e
      p "ERROR: Userinfo request failed! " + e.message
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
  redirect to($myhost + '/login')
end

def getUser(identity)
  return nil if identity.nil? or $knownIdentities[identity].nil?
  return CGI.escapeHTML($knownIdentities[identity]["full_name"]) unless $knownIdentities[identity]["full_name"].nil?
  return CGI.escapeHTML($knownIdentities[identity]["sub"])
end

get '/' do
  identity = session["user"]

  if (!identity.nil?)
    $messages[identity] = $defaultMessages.dup if $messages[identity].nil?
    token = $knownIdentities[identity]
    if (!token.nil?)
      email = token["email"]
      return haml :info, :locals => {
        :user => getUser(identity),
        :title => "Welcome.",
        :subtitle => "Welcome back #{getUser(identity)} (#{CGI.escapeHTML(email)} #{getFhgUid(identity)})",
        :messages => $messages[identity],
        :content => ""}
    end
  end

  redirect $myhost + "/login"
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
    redirect $myhost + "/access_denied?error_description=#{params["error_description"]}"
  else
    if (params["error"] != nil)
      p params["error"]
      p "ERROR! unhandled/unexpected error occurred"
      redirect $myhost + "/"
    end
  end

  if (!identity.nil?)
    token = $knownIdentities[identity]
    p token

    if (!token.nil?)
      redirect $myhost + "/"
    end

  end

  if (!id_ticket.nil?)
    begin
      identity = exchange_code_for_token(id_ticket, $nonces[session["id"]], $code_verifier[session["id"]])
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
          :authorization_endpoint => $authorization_endpoint,
          :redicret_uri => $redirect_uri,
          :client_id => $client_id,
          :messages => $defaultMessages
        }
      end
      #Handle token contents
      redirect $myhost + "/"
    rescue Exception => e
      puts e.message
      puts e.backtrace.inspect
      return CGI.escapeHTML(e.message)
    end
  end
  nonce = rand(100000)
  session["id"] = rand(100000)
  $nonces[session["id"]] = nonce
  $code_verifier[session["id"]] = SecureRandom.urlsafe_base64(64)
  digest = Digest::SHA256.new
  digest << $code_verifier[session["id"]]
  code_challenge = digest.base64digest.gsub("+", "-").gsub("/", "_").gsub("=","")
  return haml :login, :locals => {
    :user => getUser(nil),
    :title => "Login",
    :subtitle => "To use the re:claim messaging board, you must first authenticate yourself!",
    :nonce => nonce,
    :code_challenge => code_challenge,
    :authorization_endpoint => $authorization_endpoint,
    :redirect_uri => $redirect_uri,
    :client_id => $client_id,
    :messages => $defaultMessages
  }
end

get "/submit" do
  identity = session["user"]

  if (!identity.nil?)
    token = $knownIdentities[identity]
    if (!token.nil?)
      email = token["email"]
      msg = {:senderEmail=>CGI.escapeHTML(email),
             :senderName=>CGI.escapeHTML($knownIdentities[identity]["full_name"]),
             :message=>CGI.escapeHTML(params["message"])}
      $messages[identity] << msg
      redirect($myhost)
    end
  end

end


# catch-all error handler
# redirect back to main page (login) in case of errors
error do
  redirect($myhost)
end
