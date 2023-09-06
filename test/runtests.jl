import JSONWebTokens, SHA, MbedTLS, JSON

using Test
using Random

const list_of_additional_header_dicts = [
    Dict(),
    Dict("kid" => "abc12345"),
    Dict("foo" => "bar", "hello" => "world"),
]

@testset "base64url_encode/decode" begin
    header = """{"alg":"HS256","typ":"JWT"}"""
    claims = """{"sub":"1234567890","name":"John Doe","iat":1516239022}"""
    secret = "123"
    header_and_claims_encoded = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
    @test JSONWebTokens.base64url_encode(header) * "." * JSONWebTokens.base64url_encode(claims) == header_and_claims_encoded
    @test JSONWebTokens.base64url_encode(SHA.hmac_sha2_256( JSONWebTokens.to_byte_array(secret), header_and_claims_encoded)) == "pF3q46_CLIyP_1QZPpeccbs-hC4n9YW2VMBjKrSO6Wg"
    encoding = JSONWebTokens.None()
    show(IOBuffer(), encoding)
    claims_dict = JSON.parse(claims)
    @test JSONWebTokens.decode(encoding, JSONWebTokens.encode(encoding, claims_dict)) == claims_dict
    for additional_header_dict in list_of_additional_header_dicts
        @test JSONWebTokens.decode(encoding, JSONWebTokens.encode(encoding, claims_dict; additional_header_dict = additional_header_dict)) == claims_dict
    end
end

@testset "HS256 valid JSONWebTokens decode" begin
    jwt_encoded = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.8TLPbKjmE0uGLQyLnfHx2z-zy6G8qu5zFFXRSuJID_Y"
    encoding = JSONWebTokens.HS256("secretkey")
    show(IOBuffer(), encoding)
    json = JSONWebTokens.decode_as_json(encoding, jwt_encoded)
    println("JSON: $json")
    claims_dict = JSONWebTokens.decode(encoding, jwt_encoded)
    @test claims_dict["sub"] == "1234567890"
    @test claims_dict["name"] == "John Doe"
    @test claims_dict["iat"] == 1516239022
end

@testset "HS256 invalid JSONWebTokens decode" begin
    encoding = JSONWebTokens.HS256("secretkey")
    jwt_encoded_invalid_1 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.8TLPbKjmE0uGLQyLnfHx2z-zy6G8qu5zFFXRSuJID_Y"
    jwt_encoded_invalid_2 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.8TLPbKjmE0uGLQyLnfHx2z-zy6G8qu5zFFXRSuJJD_Y"
    @test_throws JSONWebTokens.InvalidSignatureError JSONWebTokens.decode(encoding, jwt_encoded_invalid_1)
    @test_throws JSONWebTokens.InvalidSignatureError JSONWebTokens.decode(encoding, jwt_encoded_invalid_2)
end

@testset "HS256 encode/decode" begin
    encoding = JSONWebTokens.HS256("secretkey")
    claims_json = """{"sub":"1234567890","name":"John Doe","iat":1516239022}"""
    claims_dict = JSON.parse(claims_json)
    @test JSONWebTokens.encode(encoding, claims_json) == "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.eLWVGTagnM7bixRmtk8GQHLzC10ZdAJlRjWyD2NDwzQ"
    @test JSONWebTokens.decode(encoding, JSONWebTokens.encode(encoding, claims_dict)) == claims_dict
    for additional_header_dict in list_of_additional_header_dicts
        @test JSONWebTokens.decode(encoding, JSONWebTokens.encode(encoding, claims_dict; additional_header_dict = additional_header_dict)) == claims_dict
    end
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
    @test JSONWebTokens.base64url_encode(header) * "." * JSONWebTokens.base64url_encode(claims) == header_and_claims_encoded

    private_key_file = joinpath(@__DIR__, "private.pem")
    @assert isfile(private_key_file) "Couldn't find test private key file $private_key_file."
    key = MbedTLS.parse_keyfile(private_key_file)
    _hash = MbedTLS.digest(MbedTLS.MD_SHA256, header_and_claims_encoded)
    output = MbedTLS.sign(key, MbedTLS.MD_SHA256, _hash, MersenneTwister(0))
    @test JSONWebTokens.base64url_encode(output) == signature_encoded

    public_key_file = joinpath(@__DIR__, "public.pem")
    @assert isfile(public_key_file) "Couldn't find test public key file $public_key_file."
    pubkey_string = read(open(public_key_file, "r"))
    pubkey = MbedTLS.PKContext()
    MbedTLS.parse_public_key!(pubkey, pubkey_string)
    @test MbedTLS.verify(pubkey, MbedTLS.MD_SHA256, _hash, JSONWebTokens.base64url_decode(signature_encoded)) == 0
end

@testset "RSA - keys in files" begin
    fp_public = joinpath(@__DIR__, "public.pem")
    fp_private = joinpath(@__DIR__, "private.pem")
    @assert isfile(fp_public)
    @assert isfile(fp_private)
    rsa_public = JSONWebTokens.RS256(fp_public)
    rsa_private = JSONWebTokens.RS256(fp_private)
    show(IOBuffer(), rsa_public)
    show(IOBuffer(), rsa_private)

    claims_dict = JSON.parse("""{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022}""")
    jwt = JSONWebTokens.encode(rsa_private, claims_dict)
    @test startswith(jwt, "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.")
    @test JSONWebTokens.decode(rsa_public, jwt) == claims_dict
    for additional_header_dict in list_of_additional_header_dicts
        jwt = JSONWebTokens.encode(rsa_private, claims_dict; additional_header_dict = additional_header_dict)
        @test JSONWebTokens.decode(rsa_public, jwt) == claims_dict
    end

    fp_public2 = joinpath(@__DIR__, "public2.pem")
    fp_private2 = joinpath(@__DIR__, "private2.pem")
    @assert isfile(fp_public2)
    @assert isfile(fp_private2)
    rsa_public2 = JSONWebTokens.RS256(fp_public2)
    rsa_private2 = JSONWebTokens.RS256(fp_private2)

    @test_throws JSONWebTokens.InvalidSignatureError JSONWebTokens.decode(rsa_public2, jwt)
    jwt2 = JSONWebTokens.encode(rsa_private2, claims_dict)
    @test jwt != jwt2
    @test JSONWebTokens.decode(rsa_public2, jwt2) == claims_dict
    @test_throws JSONWebTokens.InvalidSignatureError JSONWebTokens.decode(rsa_public, jwt2)

    @test_throws AssertionError JSONWebTokens.encode(rsa_public, claims_dict)
end

@testset "RSA - keys inline" begin

    public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwh4KT/453FE+H2myUOtY
MJlyDMtkElgdM2G8CkupqbTy7ucCgMb5rrNGKW22ZdyAoPDXCkpqc0jkCEco1nKi
wYNE4nfcit1MDUwOqXWMVgYUsFZNQEqBYUKxJYApXbiaybkKw7Yn26VFu6+culTN
+05RXSg2I6gYcWoiQMjnPqcrvTlhYRbCLW+0+bISKSoUxm5hRV6FwfEmR30LWtaF
jHIUNHAX9dg+PVGrKPgK85T4uXKI4SNg6h+Rvgty2pQ9XMbkdli5j/450oWFOa6F
NJfYQZOX5DMLOIWKOOM0IPCmRwBxzTpOCVgvc7g1KBnw1efzdwhZo1yp5PmqbiLC
gQIDAQAB
-----END PUBLIC KEY-----"""

    private_key = """-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAwh4KT/453FE+H2myUOtYMJlyDMtkElgdM2G8CkupqbTy7ucC
gMb5rrNGKW22ZdyAoPDXCkpqc0jkCEco1nKiwYNE4nfcit1MDUwOqXWMVgYUsFZN
QEqBYUKxJYApXbiaybkKw7Yn26VFu6+culTN+05RXSg2I6gYcWoiQMjnPqcrvTlh
YRbCLW+0+bISKSoUxm5hRV6FwfEmR30LWtaFjHIUNHAX9dg+PVGrKPgK85T4uXKI
4SNg6h+Rvgty2pQ9XMbkdli5j/450oWFOa6FNJfYQZOX5DMLOIWKOOM0IPCmRwBx
zTpOCVgvc7g1KBnw1efzdwhZo1yp5PmqbiLCgQIDAQABAoIBAGDgYx8m7jNw7EL7
Gf3eZiXi/pM6ElhBV1lkRlcRCbxjTPZDnfEs3ED+wV49ndDaKeuoJnnBR7z/PKaQ
9OWJUoam/4LSdONsq97a/Vo/CumHoV2bxHP4evdSNFxVyM84KS/RRHkF+IBazCFt
9Bbd6eqoXFzUi6hh5Mj9Qdj5KscOAmore/4HYw5DkzuNvtutgUaPx7SA+LwBobXP
NfVG+EKjIWan4XVUbm8QwgCdYqbpY2s5NFZMq/zu6mFGz2my73fZyCIRy0reOs5x
dg9A8xrjXMWMU8HsCAqS6o+3FXgQBmupMd53S6PAsjM7CHVS2we8T0nY1Yqfiylx
nhUZ9H0CgYEA5CbJd2RJ+9asqT+ykTKFV3qlt9Nq1Z2s7QHTfbLOPc6Jm4f+bXgD
C2Ae2v3YvSCHVs40WkJHwJA715AZm9rtlSE4QdzVCxr4D0vhbdhp7CPArnCSeyAF
Yoqt7ZHCbm3JhM31OBOwJJuRZ2jZobzTsvOCX8vyTxT6svyU9/vXtfMCgYEA2c/D
b3dib34ShJtY8MMTcCTiAv4PGrsbYF9p+9OPKvL4+na5gH9mKmwukgLBSnzeesle
ywpk2yy2Y/J3HSIOW1FUgu64bt9l0MKEFx+3Vwex3rllqhMFp7AozRLw3H+5olMT
5syy9ql8kMSsqEB9OWERQ3CJ5P2Qx6XlcsCAPrsCgYACscqTVGXjSYfEf/IV8OjO
Pa6TWzXZzADs06axx1jUNgo+Af8pP8+ZZMs4fuL+aNHwXoMTxdCfH5T1WMhUpONF
bZ0Ceh8yAGGJnLXO3E1z8oAmD0JLnfcyULz5H02SjE1i+iO5Q9JCvGudMwnO9THy
3RlfFEOKV48WahFAVIMZrQKBgCgZ6l+BWWwxh/NGLq/VGqURBVOLtvgy7q1lo7ur
jbZYmaJzbV/NFOBGnqRfQXsXVlbA8GTtevgnWUU5hNimRoJljOu2S9qN4s72oR8o
xbaOQh9Bfwg7DFV9R2XKUPInyeOq7AUYNvLW7Yoxy6AGj4ea6XTDKYAxdxBq6L2h
13q1AoGAZ6szDCRLW+69n+QKPlujfM8CSjDofnLLvr9RHSuIiFv3+moWXPPUQJf5
Gt/YOYUZ+k9mfMpC5OIrE/O+9NlUYciwl6wwJjdK9GBJuAQNqa1ZwtEioPYO3ZW6
hL1Hq+f0MJkBnql53kFDSth1fQSkSMMHIb1LGFYmoT3mSDwHDho=
-----END RSA PRIVATE KEY-----"""

    rsa_public = JSONWebTokens.RS256(public_key)
    rsa_private = JSONWebTokens.RS256(private_key)
    show(IOBuffer(), rsa_public)
    show(IOBuffer(), rsa_private)

    claims_dict = JSON.parse("""{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022}""")
    jwt = JSONWebTokens.encode(rsa_private, claims_dict)
    @test startswith(jwt, "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.")
    @test JSONWebTokens.decode(rsa_public, jwt) == claims_dict
    @testset "base64 encoded key" begin
        pub_key_encoded = JSONWebTokens.Base64.base64encode(public_key)
        rsa_public = JSONWebTokens.RS256(pub_key_encoded)
        @test JSONWebTokens.decode(rsa_public, jwt) == claims_dict
    end

    for additional_header_dict in list_of_additional_header_dicts
        jwt = JSONWebTokens.encode(rsa_private, claims_dict; additional_header_dict = additional_header_dict)
        @test JSONWebTokens.decode(rsa_public, jwt) == claims_dict
        @testset "base64 encoded key" begin
            pub_key_encoded = JSONWebTokens.Base64.base64encode(public_key)
            rsa_public = JSONWebTokens.RS256(pub_key_encoded)
            @test JSONWebTokens.decode(rsa_public, jwt) == claims_dict
        end
    end
end

@testset "private key - different prefix" begin
    private_key = """-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDpfdYaKQcs1fg4
+nDHQLLV+UX1uNb/5nAnGkSgv+K2bWBnpnqGsGX1Gp/AsYjWA/R5SfWe5UZoFvdu
rAWCM8+y8gJwU1jRuEYUeCDKft4TYgFikdcmpsnVmo+R8dIKviji+drZcZuW3cqR
/+d7nSpbT2OOWbaENOJE/NYmQa4Ha4wKqch1YuD/qjTiB5xPGcNqX14/Z02iitA/
+c/TF9itfNLMkFp5ILD6z4yFtEgMZpk+2ohEKkZiU4KxZwxjTr8xJWGzkGxQKQKJ
m8uc8PRgYxl4dq/KLK6UUtkBwb1ktWiYRu7h++tiUAqkUblOCFO3duHGWlziizY6
+somCdcDAgMBAAECggEAIprczXnBL3ry0/cCGfXTy3SrUrS3YKvVeWYiP7TQs/rX
6+S3ihjAs6fjf1qQji993y//8DHI0op813E1S8vD/6Bwjhc8NbDa6hO3wGs3HKZM
0EAPJBJaHYdPufCeEauHQcSIE+wLhDuQ1zyXITH04h2NAr73FvcDhff3ASqA0WZt
nSXMLt/z9IEh3yR7DjTsO1efATMLIbydM7Hy1GmIEo4oqlsKWz0KHe6IrtjUoUu0
8RQGQkMBcGhp8gABoAqoj/Y2kbkzvZqeUTpo8kgzcNBhdQ/kGmrYjGbkMSTjzEyd
L321GWO6TmcocpX6ElfUU39DgzpYeFYuSmOMjde8gQKBgQD2MaOw/2APEM327pTP
rna886Rr0Kw4IfhnS255lUPvP1nllw9Q/hd0BwfAZl8rIGqQcoXFRdGp4QA9zymt
lDk6FIDOH9lu6/DF/Mu0mvt7kyZpfkdECFzw8u8Xcu+P4MfATLE/bgp5agT/NqCy
cKozQ3DIvQfcPGMgTmZ6PBS6QQKBgQDyyqzQTqhDiybSHpxpMWML8F56wLKxpL1Y
oem0loi0RFr7HJQgbgFtXqo8T8nVQV7WnwZ5Zhq7/X6JeodInZRHSiqVvWqs+648
gFp7nkZkt7wj1BdM6XPxNBP1oyPAoceBwmb+GRIb3CiZyUuXBqT7SDQx52fA95Sv
F7qiy2cYQwKBgQCkAf+lawsIHk7HgLrb+8KYL8tKE9KW9nJwBb1L+9cs68wsecy3
TP48ym4si0Y9CbRUFCbve4qoG/84Lej6/LJ+8ae5KViFX2Kf0r+1ykVcVnQRdRFu
zg90aLJEscnL1JfdkHnH4rvRlIJNrouxNAL+caAR6nPxEL2MiQ4Vwi6gwQKBgQCA
xCkfWXg4SmbObdm6mKzVOiiBpg2f1aVuioDufCAIq3AtWhzdjjpHjTtwPUjoR4FL
BpBidlqbdXhU5Z02UAzCOn2XaRxYnirsf459nZXr+N5ZijTJX89UD7C+SEW/9o1f
LoF9JkLKb9tApNfoQ2fgtYypIveOCkDbFBSyHnqRDQKBgQC5nLloja1VudR0uBNg
JQmkJqrhO4s+fwx9+PIDRycI/UOxfI4XCIFUS9jFgjKWCh9TWBX8jJNM22FT3WnS
hdYV60DqxNmfKdNolXAj8kzhpmmukJ1VAsVJYkrNqsE298FEDCOGqWVGAL9FerjT
IHkGhtMpH1DU8l9tK/CWT1rVYg==
-----END PRIVATE KEY-----"""

    public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6X3WGikHLNX4OPpwx0Cy
1flF9bjW/+ZwJxpEoL/itm1gZ6Z6hrBl9RqfwLGI1gP0eUn1nuVGaBb3bqwFgjPP
svICcFNY0bhGFHggyn7eE2IBYpHXJqbJ1ZqPkfHSCr4o4vna2XGblt3Kkf/ne50q
W09jjlm2hDTiRPzWJkGuB2uMCqnIdWLg/6o04gecTxnDal9eP2dNoorQP/nP0xfY
rXzSzJBaeSCw+s+MhbRIDGaZPtqIRCpGYlOCsWcMY06/MSVhs5BsUCkCiZvLnPD0
YGMZeHavyiyulFLZAcG9ZLVomEbu4fvrYlAKpFG5TghTt3bhxlpc4os2OvrKJgnX
AwIDAQAB
-----END PUBLIC KEY-----"""

    @test JSONWebTokens.has_private_key_prefix(private_key)

    rsa_public = JSONWebTokens.RS256(public_key)
    rsa_private = JSONWebTokens.RS256(private_key)
    show(IOBuffer(), rsa_public)
    show(IOBuffer(), rsa_private)

    claims_dict = JSON.parse("""{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022}""")
    jwt = JSONWebTokens.encode(rsa_private, claims_dict)
    @test startswith(jwt, "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.")
    @test JSONWebTokens.decode(rsa_public, jwt) == claims_dict
    @testset "base64 encoded key" begin
        pub_key_encoded = JSONWebTokens.Base64.base64encode(public_key)
        rsa_public = JSONWebTokens.RS256(pub_key_encoded)
        @test JSONWebTokens.decode(rsa_public, jwt) == claims_dict
    end

    for additional_header_dict in list_of_additional_header_dicts
        jwt = JSONWebTokens.encode(rsa_private, claims_dict; additional_header_dict = additional_header_dict)
        @test JSONWebTokens.decode(rsa_public, jwt) == claims_dict
        @testset "base64 encoded key" begin
            pub_key_encoded = JSONWebTokens.Base64.base64encode(public_key)
            rsa_public = JSONWebTokens.RS256(pub_key_encoded)
            @test JSONWebTokens.decode(rsa_public, jwt) == claims_dict
        end
    end
end

@testset "header_claims.jl" begin
    @testset "_header_json" begin
        encoding = JSONWebTokens.None()
        @test_throws ErrorException JSONWebTokens._header_json(encoding; additional_header_dict = Dict("alg" => ""))
        @test_throws ErrorException JSONWebTokens._header_json(encoding; additional_header_dict = Dict("typ" => ""))
    end
end

@testset "errors.jl" begin
    @test JSONWebTokens.InvalidSignatureError() isa Exception
    @test JSONWebTokens.MalformedJWTError("foo") isa Exception
    @test JSONWebTokens.NotSupportedJWTError("foo") isa Exception
end
