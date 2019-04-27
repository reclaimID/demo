require 'sinatra'
require 'sinatra/cookies'
require 'json'
require 'base64'
require 'date'
require 'net/http'
require 'json'
require 'jwt'
require 'cgi'

enable :sessions

set :bind, '0.0.0.0'
set :show_exceptions, false

requiredInfo = [ "email", "name" ]

knownUserKeys = Array.new

$knownIdentities = {}
$passwords = {}
$codes = {}
$nonces = {}
$tokens = {}

$demo_pkey = JSON.parse(`curl --socks5-hostname '#{ENV['RECLAIM_RUNTIME']}':7777 https://api.reclaim/identity/name/reclaim`)["pubkey"]
p $demo_pkey
$reclaimEndpoint = ARGV[0]

def exchange_code_for_token(id_ticket, expected_nonce)
    cmd = "curl -X POST --socks5-hostname #{ENV['RECLAIM_RUNTIME']}:7777 'https://api.reclaim/openid/token?grant_type=authorization_code&redirect_uri=https://demo.#{$demo_pkey}/login&code=#{CGI.escape(id_ticket)}' -u #{$demo_pkey}:#{ENV["PSW_SECRET"]}"
    p "Executing: "+cmd
    resp = `#{cmd}`

    p resp

    json = JSON.parse(resp)
    return nil if json.nil? or json.empty?
    id_token = json["id_token"]
    access_token = json["access_token"]

    #                      JWT     pwd  validation (have no key)
    payload = JWT.decode(id_token, ENV["JWT_SECRET"], true,  {algorithm: 'HS512' })[0] # 0 is payload, 1 is header

    resp = `curl -X POST --socks5-hostname '#{ENV['RECLAIM_RUNTIME']}':7777 'https://api.reclaim/openid/userinfo' -H 'Authorization: Bearer #{access_token}'`

    return nil if id_token.nil?

    payload_userinfo = JSON.parse(resp)
    return nil unless expected_nonce == payload["nonce"].to_i

    identity = payload["iss"]
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
        :subtitle => "Access was Denied",
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
        identity = exchange_code_for_token(id_ticket, $nonces[session["id"]])
        $nonces[session["id"]] = nil
        if (identity.nil?)
            return "Error!"
        end
        token = $knownIdentities[identity]
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
            :subtitle => "To use the re:claim messaging board, you must first authenticate yourself!",
            :nonce => nonce,
            :reclaimEndpoint => $reclaimEndpoint,
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
