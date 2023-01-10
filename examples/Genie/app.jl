using Genie
using JSONWebTokens
using Genie.Renderer.Json

function generateToken(user)
    jwt_secret_key = ENV["JWT_SECRET_KEY"]
    encoding = JSONWebTokens.HS256(jwt_secret_key)
    jwt = JSONWebTokens.encode(encoding, user)
    return jwt
end

route("/api/create_new_user", method = POST) do
    user = Dict( "sub" => "1234567890", "name" => "John Doe", "iat" => 1516239022)
    return generateToken(user) |> json
end

route("/user/validateToken",  method = GET) do
    headers = Dict(req.headers)
    auth_header = headers["Authorization"]
    @info auth_header
    # token = split(auth_header, " ")[1]
    # @info token
end