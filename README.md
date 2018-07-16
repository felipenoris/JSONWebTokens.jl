
# JWT.jl

[![License](http://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat)](LICENSE)
[![Build Status](https://travis-ci.org/felipenoris/JWT.jl.svg?branch=master)](https://travis-ci.org/felipenoris/JWT.jl)
[![codecov.io](http://codecov.io/github/felipenoris/JWT.jl/coverage.svg?branch=master)](http://codecov.io/github/felipenoris/JWT.jl?branch=master)

A [JWT](https://jwt.io/) implementation in Julia.

# Usage

Encode:

```julia
using JWT
encoding = JWT.HS256("secretkey") # select HS256 encoding
claims_dict = Dict( "sub" => "1234567890", "name" => "John Doe", "iat" => 1516239022)
jwt = JWT.encode(encoding, claims_dict)
```

```
"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.TjUTSL0RQayQG-y_h2Tl3FmAgxhC0fYtmeiU7jnMdXY"
```

Decode:

```julia
JWT.decode(encoding, JWT.encode(encoding, claims_dict))
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
