using Genie
using JSONWebTokens
using Genie.Renderer.Json
using Genie.Requests
using Genie.Responses
using Genie.Cookies

function generateToken(user)
    jwt_secret_key = ENV["JWT_SECRET_KEY"]
    encoding = JSONWebTokens.HS256(jwt_secret_key)
    jwttoken = JSONWebTokens.encode(encoding, user)
    return jwttoken
    #Genie.Cookies.set!(Genie.Response.getresponse(), {"token" => jwttoken});
end

route("/api/create_new_user", method = POST) do
    user = Dict( "sub" => "1234567890", "name" => "John Doe", "iat" => 1516239022)
    token = generateToken(user)
    Genie.Cookies.set!(Genie.Responses.getresponse(), :token, token, Dict(
        "httponly" => true,
        "maxage" => 3600
    ))
end

route("/user/validateToken",  method = GET) do
    req = Genie.Requests.request()
    @info req
    @info req.headers
    @info req.headers
    # @info Genie.Requests.request.headers
    # @info Genie.Requets.request.headers["Authorization"]
    # headers = Dict(req.headers)
    # auth_header = headers["Authorization"]
    # @info auth_header
    # token = split(auth_header, " ")[1]
    # @info token
end