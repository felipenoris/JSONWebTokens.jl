
struct RS{bits} <: Encoding
    key::MbedTLS.PKContext
end

function RS{bits}(key_filepath::AbstractString) where {bits}
    @assert isfile(key_filepath) "Key file $key_filepath not found."
    key_as_bytes = read(open(key_filepath, "r"))
    key_as_string = String(key_as_bytes)

    if startswith(key_as_string, "-----BEGIN PUBLIC KEY-----")
        # public key
        context = MbedTLS.PKContext()
        MbedTLS.parse_public_key!(context, key_as_bytes)
        return RS{bits}(context)
    elseif startswith(key_as_string, "-----BEGIN RSA PRIVATE KEY-----")
        # private key
        key = MbedTLS.parse_keyfile(key_filepath)
        return RS{bits}(key)
    else
        error("$key_filepath is not a valid RSA public or private key.")
    end
end
