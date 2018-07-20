
struct RS{bits} <: Encoding
    key::MbedTLS.PKContext
    is_private_key::Bool
end

alg(::RS{bits}) where {bits} = "RS$(bits)"

"RSASSA using SHA-256 hash algorithm"
const RS256 = RS{256}

"RSASSA using SHA-384 hash algorithm"
const RS384 = RS{384}

md_hash_alg(::RS256) = MbedTLS.MD_SHA256
md_hash_alg(::RS384) = MbedTLS.MD_SHA384

function RS{bits}(key_filepath::AbstractString) where {bits}
    @assert isfile(key_filepath) "Key file $key_filepath not found."
    key_as_bytes = read(open(key_filepath, "r"))
    key_as_string = String(key_as_bytes)
    context = MbedTLS.PKContext()

    if startswith(key_as_string, "-----BEGIN PUBLIC KEY-----")
        # public key
        MbedTLS.parse_public_key!(context, key_as_bytes)
        return RS{bits}(context, false)
    elseif startswith(key_as_string, "-----BEGIN RSA PRIVATE KEY-----")
        # private key
        MbedTLS.parse_key!(context, key_as_bytes)
        return RS{bits}(context, true)
    else
        error("$key_filepath is not a valid RSA public or private key.")
    end
end

function sign(encoding::RS, data)
    @assert encoding.is_private_key "Must sign using a private key."
    md = md_hash_alg(encoding)
    signature = MbedTLS.sign(encoding.key, md, MbedTLS.digest(md, data), MersenneTwister(0))
    return base64url_encode(signature)
end

function has_valid_signature(encoding::RS, header_and_claims_encoded::AbstractString, signature_encoded::AbstractString) :: Bool
    try
        md = md_hash_alg(encoding)
        _hash = MbedTLS.digest(md, header_and_claims_encoded)
        return MbedTLS.verify(encoding.key, md, _hash, base64url_decode(signature_encoded)) == 0
    catch e
        return false
    end
end
