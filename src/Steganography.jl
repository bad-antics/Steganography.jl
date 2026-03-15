"""
    Steganography

LSB (Least Significant Bit) image steganography for Julia.

Hide secret data in images by modifying the least significant bits of pixel
values. Supports grayscale and color images via Netpbm (PGM/PPM) format
with zero external dependencies.

# Quick Start
```julia
using Steganography

# Hide a message in an image
encode_file("cover.ppm", "stego.ppm", "secret message")

# Extract the hidden message
message = decode_file("stego.ppm")
println(message)  # => "secret message"
```

# Working with raw pixel data
```julia
pixels = rand(UInt8, 100, 100, 3)  # RGB image
stego = encode(pixels, "hidden data")
recovered = decode(stego)
println(String(recovered))  # => "hidden data"
```
"""
module Steganography

export encode, decode, encode!, capacity,
       encode_file, decode_file,
       read_netpbm, write_netpbm,
       StegoConfig

# ─────────────────────────────────────────────────────────────────────────────
#                              CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

"""
    StegoConfig

Configuration for steganographic encoding/decoding.

# Fields
- `bits_per_channel::Int`: Number of LSBs to use per channel (1, 2, or 4). Default: 1
"""
struct StegoConfig
    bits_per_channel::Int
    
    function StegoConfig(; bits_per_channel::Int = 1)
        bits_per_channel in (1, 2, 4) || error("bits_per_channel must be 1, 2, or 4")
        new(bits_per_channel)
    end
end

# ─────────────────────────────────────────────────────────────────────────────
#                              CAPACITY
# ─────────────────────────────────────────────────────────────────────────────

"""
    capacity(pixels::AbstractArray{UInt8}; config=StegoConfig()) -> Int

Return the maximum number of bytes that can be hidden in the given pixel data.

Accounts for the 4-byte length header that is prepended to the payload.
"""
function capacity(pixels::AbstractArray{UInt8}; config::StegoConfig = StegoConfig())
    total_bits = length(pixels) * config.bits_per_channel
    total_bytes = total_bits ÷ 8
    # Reserve 4 bytes for the length header
    return max(0, total_bytes - 4)
end

# ─────────────────────────────────────────────────────────────────────────────
#                              LSB ENCODING
# ─────────────────────────────────────────────────────────────────────────────

"""
    encode(pixels::AbstractArray{UInt8}, data::Vector{UInt8}; config=StegoConfig()) -> Array{UInt8}

Encode binary data into a copy of the pixel array using LSB steganography.

Returns a new array with the data hidden in the least significant bits.
A 4-byte big-endian length header is prepended to enable extraction.

# Arguments
- `pixels`: Cover image pixel data (any shape)
- `data`: Data to hide
- `config`: Steganographic configuration
"""
function encode(pixels::AbstractArray{UInt8}, data::Vector{UInt8};
                config::StegoConfig = StegoConfig())
    result = copy(pixels)
    encode!(result, data; config=config)
    return result
end

"""
    encode(pixels::AbstractArray{UInt8}, message::String; config=StegoConfig()) -> Array{UInt8}

Encode a string message into pixel data.
"""
encode(pixels::AbstractArray{UInt8}, message::String; kwargs...) =
    encode(pixels, Vector{UInt8}(message); kwargs...)

"""
    encode!(pixels::AbstractArray{UInt8}, data::Vector{UInt8}; config=StegoConfig())

Encode data into pixels in-place using LSB steganography.
"""
function encode!(pixels::AbstractArray{UInt8}, data::Vector{UInt8};
                 config::StegoConfig = StegoConfig())
    
    cap = capacity(pixels; config=config)
    length(data) <= cap || error(
        "Data too large: $(length(data)) bytes, capacity is $cap bytes " *
        "($(length(pixels)) pixels × $(config.bits_per_channel) bits)"
    )
    
    # Prepend 4-byte big-endian length
    len = UInt32(length(data))
    payload = vcat(
        UInt8[(len >> 24) & 0xff, (len >> 16) & 0xff, (len >> 8) & 0xff, len & 0xff],
        data
    )
    
    bpc = config.bits_per_channel
    mask = UInt8((1 << bpc) - 1)          # Bits to extract from data
    channel_mask = UInt8(~mask)            # Clear LSBs of pixel
    
    pixel_idx = 1
    
    for byte in payload
        # Spread this byte across pixels using `bpc` bits each
        bits_remaining = 8
        while bits_remaining > 0
            bits_remaining -= bpc
            # Extract `bpc` bits from current position in byte
            chunk = (byte >> bits_remaining) & mask
            # Clear LSBs of pixel and insert chunk
            pixels[pixel_idx] = (pixels[pixel_idx] & channel_mask) | chunk
            pixel_idx += 1
        end
    end
    
    return pixels
end

"""
    encode!(pixels::AbstractArray{UInt8}, message::String; kwargs...)

Encode a string message in-place.
"""
encode!(pixels::AbstractArray{UInt8}, message::String; kwargs...) =
    encode!(pixels, Vector{UInt8}(message); kwargs...)

# ─────────────────────────────────────────────────────────────────────────────
#                              LSB DECODING
# ─────────────────────────────────────────────────────────────────────────────

"""
    decode(pixels::AbstractArray{UInt8}; config=StegoConfig()) -> Vector{UInt8}

Extract hidden data from pixel data using LSB steganography.

Reads the 4-byte length header first, then extracts the payload.
"""
function decode(pixels::AbstractArray{UInt8};
                config::StegoConfig = StegoConfig())
    
    bpc = config.bits_per_channel
    pixels_per_byte = 8 ÷ bpc
    mask = UInt8((1 << bpc) - 1)
    
    # Need at least 4 bytes for the length header
    min_pixels = 4 * pixels_per_byte
    length(pixels) >= min_pixels || error("Image too small to contain hidden data")
    
    # Extract length header (4 bytes)
    header = _extract_bytes(pixels, 1, 4, bpc, mask)
    payload_len = (UInt32(header[1]) << 24) | (UInt32(header[2]) << 16) |
                  (UInt32(header[3]) << 8)  | UInt32(header[4])
    
    # Sanity check
    max_cap = capacity(pixels; config=config)
    payload_len <= max_cap || error(
        "Invalid payload length $payload_len (max capacity $max_cap). " *
        "Image may not contain hidden data or wrong config."
    )
    
    # Extract payload
    payload_start = min_pixels + 1
    payload = _extract_bytes(pixels, payload_start, Int(payload_len), bpc, mask)
    
    return payload
end

"""Extract `n` bytes from pixels starting at `pixel_start`."""
function _extract_bytes(pixels::AbstractArray{UInt8}, pixel_start::Int,
                        n::Int, bpc::Int, mask::UInt8)
    pixels_per_byte = 8 ÷ bpc
    result = Vector{UInt8}(undef, n)
    pixel_idx = pixel_start
    
    for i in 1:n
        byte = UInt8(0)
        for _ in 1:pixels_per_byte
            byte = (byte << bpc) | (pixels[pixel_idx] & mask)
            pixel_idx += 1
        end
        result[i] = byte
    end
    
    return result
end

# ─────────────────────────────────────────────────────────────────────────────
#                              NETPBM I/O
# ─────────────────────────────────────────────────────────────────────────────

"""
    NetpbmImage

Parsed Netpbm image (PGM P5 or PPM P6).

# Fields
- `format::String`: "P5" (grayscale) or "P6" (color)
- `width::Int`: Image width in pixels
- `height::Int`: Image height in pixels
- `maxval::Int`: Maximum pixel value (typically 255)
- `pixels::Array{UInt8}`: Pixel data — (H, W) for P5, (H, W, 3) for P6
"""
struct NetpbmImage
    format::String
    width::Int
    height::Int
    maxval::Int
    pixels::Array{UInt8}
end

"""
    read_netpbm(filepath::String) -> NetpbmImage

Read a PGM (P5) or PPM (P6) image file.
"""
function read_netpbm(filepath::String)
    data = read(filepath)
    return _parse_netpbm(data)
end

function _parse_netpbm(data::Vector{UInt8})
    pos = 1
    
    # Parse magic number
    pos, magic = _read_token(data, pos)
    magic in ("P5", "P6") || error("Unsupported format: $magic (only P5/P6 supported)")
    
    # Parse width
    pos, width_str = _read_token(data, pos)
    width = parse(Int, width_str)
    
    # Parse height
    pos, height_str = _read_token(data, pos)
    height = parse(Int, height_str)
    
    # Parse maxval
    pos, maxval_str = _read_token(data, pos)
    maxval = parse(Int, maxval_str)
    maxval == 255 || error("Only maxval=255 supported, got $maxval")
    
    # Skip exactly one whitespace byte after maxval
    pos += 1
    
    # Read pixel data
    if magic == "P5"
        npixels = width * height
        pixel_data = data[pos:pos + npixels - 1]
        pixels = reshape(pixel_data, width, height)'  # Row-major to column-major
    else  # P6
        npixels = width * height * 3
        pixel_data = data[pos:pos + npixels - 1]
        pixels = permutedims(reshape(pixel_data, 3, width, height), (3, 2, 1))
    end
    
    return NetpbmImage(magic, width, height, maxval, pixels)
end

"""Read next whitespace-delimited token, skipping comments."""
function _read_token(data::Vector{UInt8}, pos::Int)
    # Skip whitespace and comments
    while pos <= length(data)
        c = Char(data[pos])
        if c == '#'
            # Skip to end of line
            while pos <= length(data) && Char(data[pos]) != '\n'
                pos += 1
            end
            pos += 1  # skip newline
        elseif c in (' ', '\t', '\n', '\r')
            pos += 1
        else
            break
        end
    end
    
    # Read token
    start = pos
    while pos <= length(data) && !(Char(data[pos]) in (' ', '\t', '\n', '\r'))
        pos += 1
    end
    
    token = String(data[start:pos-1])
    return pos, token
end

"""
    write_netpbm(filepath::String, img::NetpbmImage)

Write a NetpbmImage to a PGM (P5) or PPM (P6) file.
"""
function write_netpbm(filepath::String, img::NetpbmImage)
    open(filepath, "w") do io
        # Write header
        write(io, "$(img.format)\n")
        write(io, "$(img.width) $(img.height)\n")
        write(io, "$(img.maxval)\n")
        
        # Write pixel data
        if img.format == "P5"
            # Transpose back to row-major
            write(io, vec(img.pixels'))
        else
            # (H, W, 3) → interleaved RGB
            for row in 1:img.height
                for col in 1:img.width
                    write(io, img.pixels[row, col, :])
                end
            end
        end
    end
end

"""
    write_netpbm(filepath::String, pixels::AbstractArray{UInt8};
                 format::String = ndims(pixels) == 3 ? "P6" : "P5")

Write raw pixel data as a Netpbm file.
"""
function write_netpbm(filepath::String, pixels::AbstractArray{UInt8};
                      format::String = ndims(pixels) == 3 ? "P6" : "P5")
    if format == "P5"
        ndims(pixels) == 2 || error("P5 format requires 2D array (H×W)")
        h, w = size(pixels)
    else
        ndims(pixels) == 3 && size(pixels, 3) == 3 || 
            error("P6 format requires 3D array (H×W×3)")
        h, w, _ = size(pixels)
    end
    img = NetpbmImage(format, w, h, 255, pixels)
    write_netpbm(filepath, img)
end

# ─────────────────────────────────────────────────────────────────────────────
#                              FILE-LEVEL API
# ─────────────────────────────────────────────────────────────────────────────

"""
    encode_file(input::String, output::String, data; config=StegoConfig())

Read a Netpbm image, encode data into it, and write the result.

`data` can be a `String`, `Vector{UInt8}`, or a file path (use `encode_file_data` for files).
"""
function encode_file(input::String, output::String, data::Union{String, Vector{UInt8}};
                     config::StegoConfig = StegoConfig())
    img = read_netpbm(input)
    payload = data isa String ? Vector{UInt8}(data) : data
    encode!(img.pixels, payload; config=config)
    write_netpbm(output, img)
    return nothing
end

"""
    decode_file(filepath::String; config=StegoConfig()) -> Vector{UInt8}

Read a Netpbm image and extract hidden data.
"""
function decode_file(filepath::String; config::StegoConfig = StegoConfig())
    img = read_netpbm(filepath)
    return decode(img.pixels; config=config)
end

end # module Steganography
