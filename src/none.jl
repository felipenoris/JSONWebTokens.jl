struct None <: Encoding
end

alg(::None) = "none"

function decode(::None, str::AbstractString)
    header_encoded, claims_encoded, signature_encoded = jws_split(str)
    return jws_claims_dict(claims_encoded)
end

function encode(
        encoding::None,
        claims_json::AbstractString;
        additional_header_dict = Dict(),
    )
    header_json = _header_json(
        encoding;
        additional_header_dict=additional_header_dict,
    )
    header_encoded = base64url_encode(header_json)
    claims_encoded = base64url_encode(claims_json)
    header_and_claims_encoded = header_encoded * "." * claims_encoded
    return header_and_claims_encoded
end
