
struct RS{bits} <: Encoding
    key::MbedTLS.PKContext
    is_private_key::Bool
end

alg(::RS{bits}) where {bits} = "RS$(bits)"

function Base.show(io::IO, encoding::RS)
    print(io, alg(encoding))

    if encoding.is_private_key
        print(io, " Private Key")
    else
        print(io, " Public Key")
    end
end

"RSASSA using SHA-256 hash algorithm"
const RS256 = RS{256}

"RSASSA using SHA-384 hash algorithm"
const RS384 = RS{384}

md_hash_alg(::RS256) = MbedTLS.MD_SHA256
md_hash_alg(::RS384) = MbedTLS.MD_SHA384

@inline function has_key_prefix(str::AbstractString)
    return startswith(str, "-----BEGIN PUBLIC KEY-----") || startswith(str, "-----BEGIN RSA PRIVATE KEY-----")
end

@inline convert_string_to_bytes(str::AbstractString) :: Vector{UInt8} = convert(Vector{UInt8}, codeunits(str))

function RS{bits}(key_or_filepath::AbstractString) where {bits}
    local key_as_bytes::Vector{UInt8}
    local key_as_string::String

    if has_key_prefix(key_or_filepath)
        key_as_string = String(key_or_filepath)
        key_as_bytes = convert_string_to_bytes(key_as_string)
    else
        @assert isfile(key_or_filepath) "$key_or_filepath is not a valid RSA public or private key."
        key_as_bytes = read(open(key_or_filepath, "r"))
        key_as_string = String(copy(key_as_bytes))
    end

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
        error("$key_or_filepath is not a valid RSA public or private key.")
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
