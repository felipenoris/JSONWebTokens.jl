
# JWT.jl

[![License](http://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat)](LICENSE)
[![Build Status](https://travis-ci.org/felipenoris/JWT.jl.svg?branch=master)](https://travis-ci.org/felipenoris/JWT.jl)
[![codecov.io](http://codecov.io/github/felipenoris/JWT.jl/coverage.svg?branch=master)](http://codecov.io/github/felipenoris/JWT.jl?branch=master)

Secure your Julia APIs with [JWT](https://jwt.io/).

# Usage

## For HMAC RSA Algorithms

Encode:

```julia
import JWT
claims_dict = Dict( "sub" => "1234567890", "name" => "John Doe", "iat" => 1516239022)
encoding = JWT.HS256("secretkey") # select HS256 encoding
jwt = JWT.encode(encoding, claims_dict)
```

```
"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.TjUTSL0RQayQG-y_h2Tl3FmAgxhC0fYtmeiU7jnMdXY"
```

Decode:

```julia
JWT.decode(encoding, jwt)
```

```
Dict{String,Any} with 3 entries:
  "name" => "John Doe"
  "sub"  => "1234567890"
  "iat"  => 1516239022
```

## For RSASSA RSA Algorithms

First, generate public and private keys. You can use `openssl`.

```shell
$ openssl genrsa -out private.pem 2048
$ openssl rsa -in private.pem -out public.pem -outform PEM -pubout
```

Use the private key to encode.

```julia
import JWT
claims_dict = Dict( "sub" => "1234567890", "name" => "John Doe", "iat" => 1516239022)
rsa_private = JWT.RS256("private.pem") # Use the filepath to private.pem
jwt = JWT.encode(rsa_private, claims_dict)
```

```
"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.HUXm8CAiY9EKX3dU1Ym7bZvL7yXMu3TC9iL1do0jvM0oD2rSqY5K06KmQy1qJETYZAIZIgA6ZrX2Q3ug01DVu-Yf1Kx3-OpC39eYuBGH-7P1QgwEcizbh6dw07LGC-xshru1v_tKi9IaogiitnEMLLeGdOuCTtYw2gDRjACq2L2UiJTAgurZ_yxE3cMApo492leubNo9fADtRPpofy37Q2VivfS4XwlTkS9Bxg6jrkBhTr-ieuiBx_kAmk2Zps5f9ih-aNPXi_3p5tNH-8LUMJ5L2CTb6Ui1ghyElI7k8wfXzQIm0fGRiQu9OBnqgm2Bh9AivquXXeX6JQGxyntDqA"
```

Use the public key to decode.

```julia
rsa_public = JWT.RS256("public.pem") # Use the filepath to public.pem
JWT.decode(rsa_public, jwt)
```

```
Dict{String,Any} with 3 entries:
  "name" => "John Doe"
  "sub"  => "1234567890"
  "iat"  => 1516239022
```

# Supported Algorithms

* HS256

* HS384

* HS512

* RS256

* RS384

# References

* [RFC7519](https://tools.ietf.org/html/rfc7519)

* [jwt.io](https://jwt.io)
