using Genie
using JSONWebTokens
using Genie.Renderer.Json
using Genie.Requests
using Genie.Responses
using Genie.Cookies
using Genie.Encryption

const jwt_secret_key = ENV["JWT_SECRET_KEY"]
const encoding = JSONWebTokens.HS256(jwt_secret_key)

function generateToken(user)
    jwttoken = JSONWebTokens.encode(encoding, user)
    return jwttoken
end

function cookie_jwt_auth(req, res)
    cookie = req["Cookie"][7:end]
    # mycookie = Genie.Cookies.getcookies(req)
    token = Genie.Encryption.decrypt(String(cookie))
    try
        user = JSONWebTokens.decode(encoding, token)
        @info user
    catch ex
        # if signature doesn't verify
        # JSONWebTokens.InvalidSignatureError()
        println(ex)
        # TODO: implement clear_cookie
        # very very very important -> res.clear_cookie
        # very very very important -> redirect to root
    end 
end

route("/login_route", method = POST) do
    user = Dict( "sub" => "1234567890", "name" => "John Doe", "iat" => 1516239022)
    token = generateToken(user)
    @info token
    Genie.Cookies.set!(Genie.Responses.getresponse(), :token, token, Dict(
        "httponly" => true,
        "maxage" => 3600
    ))
end

route("/add_route",  method = POST) do
    req = Genie.Requests.request()
    res = Genie.Responses.getresponse()
    cookie_jwt_auth(req, res)

    @info "welcome to genie!"
end