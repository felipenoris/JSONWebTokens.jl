
base64url_encode(s) = replace(Base64URL.base64encode(s), '=', "") # removes trailing padding

function base64url_decode(s::AbstractString)
    @assert isascii(s)

    # adds padding back
    r = rem(length(s), 4)
    if r > 0
        for i in 1:r
            s *= "="
        end
    end

    return Base64URL.base64decode(s)
end

find_dots(str::AbstractString) = find(x -> x == '.', str)

function jws_split(str::AbstractString)
    dot_indexes = find_dots(str)

    if isempty(dot_indexes)
        throw(MalformedJWTError("JWT must contain at least one '.' character."))
    elseif length(dot_indexes) > 2
        throw(NotSupportedJWTError("JWE format is not supported. Only JWS is supported for now."))
    end

    header = SubString(str, 1, dot_indexes[1] - 1)

    if length(dot_indexes) == 1
        claims = SubString(str, dot_indexes[1] + 1, endof(str))
        signature = ""
    else
        claims = SubString(str, dot_indexes[1] + 1, dot_indexes[2] - 1)
        signature = SubString(str, dot_indexes[2] + 1, endof(str))
    end

    return header, claims, signature
end

function jws_header_dict(header_encoded::AbstractString)
    try
        header_dict = JSON.parse(String(base64url_decode(header_encoded)))
        @assert haskey(header_dict, "alg") "\"alg\" attribute is missing."
        @assert haskey(header_dict, "typ") "\"typ\" attribute is missing."
        @assert header_dict["typ"] == "JWT" "Expected \"typ\" == \"JWT\". Found $(header_dict["typ"])."
        return header_dict
    catch e
        throw(MalformedJWTError("Couldn't parse header ($e)."))
    end
end

function jws_claims_dict(claims_encoded::AbstractString)
    try
        claims_dict = JSON.parse(String(base64url_decode(claims_encoded)))
        return claims_dict
    catch e
        throw(MalformedJWTError("Couldn't parse claims ($e)."))
    end
end

function decode(encoding::Encoding, str::AbstractString)
    header_encoded, claims_encoded, signature_encoded = jws_split(str)
    header_dict = jws_header_dict(header_encoded)

    if isempty(signature_encoded)
        throw(MalformedJWTError("Expected alg $(alg(encoding)), but found empty signature field."))
    end

    if header_dict["alg"] != alg(encoding)
        throw(MalformedJWTError("Expected alg $(alg(encoding)). Found $(header_dict["alg"])."))
    end

    verify(encoding, str)
    return jws_claims_dict(claims_encoded)
end

verify(encoding::Encoding, str::AbstractString) = !has_valid_signature(encoding, str) && throw(InvalidSignatureError())
encode(encoding::Encoding, claims_dict::Dict{S, A}) where {S<:AbstractString, A} = encode(encoding, JSON.json(claims_dict))

function encode(encoding::Encoding, claims_json::AbstractString)
    header_encoded = base64url_encode("""{"alg":"$(alg(encoding))","typ":"JWT"}""")
    claims_encoded = base64url_encode(claims_json)
    header_and_claims_encoded = header_encoded * "." * claims_encoded
    signature = sign(encoding, header_and_claims_encoded)
    return header_and_claims_encoded * "." * signature
end
