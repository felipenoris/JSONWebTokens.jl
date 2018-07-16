
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

has_valid_signature(encoding::HS, header_and_claims_encoded::AbstractString, signature_encoded::AbstractString) :: Bool = signature_encoded == sign(encoding, header_and_claims_encoded)

sign(encoding::HS256, data::AbstractString) = base64url_encode(SHA.hmac_sha2_256(encoding.key, data))
sign(encoding::HS384, data::AbstractString) = base64url_encode(SHA.hmac_sha2_384(encoding.key, data))
sign(encoding::HS512, data::AbstractString) = base64url_encode(SHA.hmac_sha2_512(encoding.key, data))
