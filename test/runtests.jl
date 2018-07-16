
using Base.Test
import JWT, SHA, MbedTLS

@testset "base64url_encode/decode" begin
    header = """{"alg":"HS256","typ":"JWT"}"""
    claims = """{"sub":"1234567890","name":"John Doe","iat":1516239022}"""
    secret = "123"
    header_and_claims_encoded = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
    @test JWT.base64url_encode(header) * "." * JWT.base64url_encode(claims) == header_and_claims_encoded
    @test JWT.base64url_encode(SHA.hmac_sha2_256(convert(Vector{UInt8}, secret), header_and_claims_encoded)) == "pF3q46_CLIyP_1QZPpeccbs-hC4n9YW2VMBjKrSO6Wg"
    encoding = JWT.None()
    claims_dict = JSON.parse(claims)
    @test JWT.decode(encoding, JWT.encode(encoding, claims_dict)) == claims_dict
end

@testset "HS256 valid JWT decode" begin
    jwt_encoded = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.8TLPbKjmE0uGLQyLnfHx2z-zy6G8qu5zFFXRSuJID_Y"
    encoding = JWT.HS256("secretkey")
    claims_dict = JWT.decode(encoding, jwt_encoded)
    @test claims_dict["sub"] == "1234567890"
    @test claims_dict["name"] == "John Doe"
    @test claims_dict["iat"] == 1516239022
end

@testset "HS256 invalid JWT decode" begin
    encoding = JWT.HS256("secretkey")
    jwt_encoded_invalid_1 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.8TLPbKjmE0uGLQyLnfHx2z-zy6G8qu5zFFXRSuJID_Y"
    jwt_encoded_invalid_2 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.8TLPbKjmE0uGLQyLnfHx2z-zy6G8qu5zFFXRSuJJD_Y"
    @test_throws JWT.InvalidSignatureError JWT.decode(encoding, jwt_encoded_invalid_1)
    @test_throws JWT.InvalidSignatureError JWT.decode(encoding, jwt_encoded_invalid_2)
end

@testset "HS256 encode/decode" begin
    encoding = JWT.HS256("secretkey")
    claims_json = """{"sub":"1234567890","name":"John Doe","iat":1516239022}"""
    claims_dict = JSON.parse(claims_json)
    @test JWT.encode(encoding, claims_json) == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.8TLPbKjmE0uGLQyLnfHx2z-zy6G8qu5zFFXRSuJID_Y"
    @test JWT.decode(encoding, JWT.encode(encoding, claims_dict)) == claims_dict
end

# how to generate public/private key using openssl
# https://www.devco.net/archives/2006/02/13/public_-_private_key_encryption_using_openssl.php

# private.pem / public.pem generated using
# $ openssl genrsa -out private.pem 2048
# $ openssl rsa -in private.pem -out public.pem -outform PEM -pubout
# $ openssl genrsa -out private2.pem 2048
# $ openssl rsa -in private2.pem -out public2.pem -outform PEM -pubout

@testset "MbedTLS" begin
    header = """{"alg":"RS256","typ":"JWT"}"""
    claims = """{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022}"""
    header_and_claims_encoded = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0"
    signature_encoded = "o9uMYrmOqgdBqhbOBzuiN_0nFp2Ed1J4urFx-TyY61AgM6tUTutTGfIsIZERVjqRXAKd6bGYPuVlGf5m-XADAmqnKTpxcaP_t5ipNfsB6g9rudi7U3uWYldbSfW0-cnayISt5Eyga23Qs5ZqY7e7uQHN_z_mI2Cmoari91ZGnt1jte11gFNd7icMDGz9laBZESeFGFECAxP2hCvrg_G0dCySh_AVnYerD0iF0MznMvV1dxxuprjeQDunQtG3h2uQrJMTBEvCVPxrf7Kql3_k9S4pQDQaoPGQPO9yogpdYdgS5OV3LdSvjlDwRQL6FlDTgB3l1sv0NkEpRviR3x9VLA"
    @test JWT.base64url_encode(header) * "." * JWT.base64url_encode(claims) == header_and_claims_encoded

    private_key_file = "private.pem"
    @assert isfile(private_key_file) "Couldn't find test private key file $private_key_file."
    key = MbedTLS.parse_keyfile(private_key_file)
    _hash = MbedTLS.digest(MbedTLS.MD_SHA256, header_and_claims_encoded)
    output = MbedTLS.sign(key, MbedTLS.MD_SHA256, _hash, MersenneTwister(0))
    @test JWT.base64url_encode(output) == signature_encoded

    public_key_file = "public.pem"
    @assert isfile(public_key_file) "Couldn't find test public key file $public_key_file."
    pubkey_string = read(open(public_key_file, "r"))
    pubkey = MbedTLS.PKContext()
    MbedTLS.parse_public_key!(pubkey, pubkey_string)
    @test MbedTLS.verify(pubkey, MbedTLS.MD_SHA256, _hash, JWT.base64url_decode(signature_encoded)) == 0
end

@testset "RSA" begin
    fp_public = "public.pem"
    fp_private = "private.pem"
    @assert isfile(fp_public)
    @assert isfile(fp_private)
    rsa_public = JWT.RS256(fp_public)
    rsa_private = JWT.RS256(fp_private)

    claims_dict = JSON.parse("""{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022}""")
    jwt = JWT.encode(rsa_private, claims_dict)
    @test startswith(jwt, "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.")
    @test JWT.decode(rsa_public, jwt) == claims_dict

    fp_public2 = "public2.pem"
    fp_private2 = "private2.pem"
    @assert isfile(fp_public2)
    @assert isfile(fp_private2)
    rsa_public2 = JWT.RS256(fp_public2)
    rsa_private2 = JWT.RS256(fp_private2)

    @test_throws JWT.InvalidSignatureError JWT.decode(rsa_public2, jwt)
    jwt2 = JWT.encode(rsa_private2, claims_dict)
    @test jwt != jwt2
    @test JWT.decode(rsa_public2, jwt2) == claims_dict
    @test_throws JWT.InvalidSignatureError JWT.decode(rsa_public, jwt2)

    @test_throws AssertionError JWT.encode(rsa_public, claims_dict)
end
