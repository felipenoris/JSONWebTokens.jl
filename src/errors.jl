
struct InvalidSignatureError <: Exception
end

struct MalformedJWTError <: Exception
    msg::String
end

struct NotSupportedJWTError <: Exception
    msg::String
end

Base.showerror(io::IO, e::InvalidSignatureError) = print(io, "Signature verification failed.")
Base.showerror(io::IO, e::MalformedJWTError) = print(io, "Malformed JWT: $(e.msg).")
Base.showerror(io::IO, e::NotSupportedJWTError) = print(io, "JWT format not supported: $(e.msg).")
