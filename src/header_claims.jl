function _header_json(
        encoding;
        additional_header_dict::AbstractDict,
    )
    # The `additional_header_dict` dictionary is not allowed to have a key named
    # "alg" or "typ", because we are going to define those keys ourselves.
    for claim in ("alg", "typ")
        if haskey(additional_header_dict, claim)
            msg = "additional_header_dict is not allowed to have a key named $(claim)"
            error(msg)
        end
    end
    header_dict = Dict{String, String}()
    for (k, v) in pairs(additional_header_dict)
        header_dict[k] = v
    end
    header_dict["typ"] = "JWT"
    header_dict["alg"] = alg(encoding)
    header_json = JSON.json(header_dict)::String
    return header_json
end
