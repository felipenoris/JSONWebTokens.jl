
# JSONWebTokens.jl

[![License][license-img]](LICENSE)
[![CI][ci-img]][ci-url]
[![codecov][codecov-img]][codecov-url]

[license-img]: http://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square
[ci-img]: https://github.com/felipenoris/JSONWebTokens.jl/workflows/CI/badge.svg
[ci-url]: https://github.com/felipenoris/JSONWebTokens.jl/actions?query=workflow%3ACI
[codecov-img]: https://img.shields.io/codecov/c/github/felipenoris/JSONWebTokens.jl/master.svg?label=codecov&style=flat-square
[codecov-url]: http://codecov.io/github/felipenoris/JSONWebTokens.jl?branch=master

Secure your Julia APIs with [JWT](https://jwt.io/).

# Requirements

Julia v1.3 or later.

# Installation

```julia
julia> import Pkg; Pkg.add("JSONWebTokens")
```

# Usage

## For HMAC RSA Algorithms

Encode:

```julia
import JSONWebTokens
claims_dict = Dict( "sub" => "1234567890", "name" => "John Doe", "iat" => 1516239022)
encoding = JSONWebTokens.HS256("secretkey") # select HS256 encoding
jwt = JSONWebTokens.encode(encoding, claims_dict)
```

```
"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.TjUTSL0RQayQG-y_h2Tl3FmAgxhC0fYtmeiU7jnMdXY"
```

Decode:

```julia
JSONWebTokens.decode(encoding, jwt)
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
import JSONWebTokens
claims_dict = Dict( "sub" => "1234567890", "name" => "John Doe", "iat" => 1516239022)
rsa_private = JSONWebTokens.RS256("private.pem") # accepts a filepath, string or base64 encoded string
jwt = JSONWebTokens.encode(rsa_private, claims_dict)
```

```
"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.HUXm8CAiY9EKX3dU1Ym7bZvL7yXMu3TC9iL1do0jvM0oD2rSqY5K06KmQy1qJETYZAIZIgA6ZrX2Q3ug01DVu-Yf1Kx3-OpC39eYuBGH-7P1QgwEcizbh6dw07LGC-xshru1v_tKi9IaogiitnEMLLeGdOuCTtYw2gDRjACq2L2UiJTAgurZ_yxE3cMApo492leubNo9fADtRPpofy37Q2VivfS4XwlTkS9Bxg6jrkBhTr-ieuiBx_kAmk2Zps5f9ih-aNPXi_3p5tNH-8LUMJ5L2CTb6Ui1ghyElI7k8wfXzQIm0fGRiQu9OBnqgm2Bh9AivquXXeX6JQGxyntDqA"
```

Use the public key to decode.

```julia
rsa_public = JSONWebTokens.RS256("public.pem") # accepts a filepath, string or base64 encoded string
JSONWebTokens.decode(rsa_public, jwt)
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
