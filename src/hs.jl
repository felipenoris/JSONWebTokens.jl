
struct HS{bits} <: Encoding
    key::Vector{UInt8}
end

"HMAC SHA-256"
const HS256 = HS{256}

"HMAC using SHA-384"
const HS384 = HS{384}

"HMAC using SHA-512"
const HS512 = HS{512}

HS{bits}(key::AbstractString) where {bits} = HS{bits}(convert(Vector{UInt8}, key))
alg(::HS{bits}) where {bits} = "HS$(bits)"

function has_valid_signature(encoding::HS, str::AbstractString) :: Bool
    last_dot_index = findlast( x -> x == '.', str)
    if last_dot_index == 0
        throw(MalformedJWTError("JWT must contain at least one '.' character."))
    end
    header_and_claims_encoded = SubString(str, 1, last_dot_index - 1)

    if endof(str) <= last_dot_index + 1
       throw(MalformedJWTError("JWT has not signature."))
    end

    signature_encoded = SubString(str, last_dot_index + 1, endof(str))
    return signature_encoded == sign(encoding, header_and_claims_encoded)
end

sign(encoding::HS256, data::AbstractString) = base64url_encode(SHA.hmac_sha2_256(encoding.key, data))
sign(encoding::HS384, data::AbstractString) = base64url_encode(SHA.hmac_sha2_384(encoding.key, data))
sign(encoding::HS512, data::AbstractString) = base64url_encode(SHA.hmac_sha2_512(encoding.key, data))
