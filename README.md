# Steganography.jl

[![CI](https://github.com/bad-antics/Steganography.jl/actions/workflows/ci.yml/badge.svg)](https://github.com/bad-antics/Steganography.jl/actions/workflows/ci.yml)

**LSB image steganography for Julia** — hide and extract secret data in images with zero external dependencies.

## Features

- **LSB steganography** — encode data in least significant bits of pixel values
- **Configurable bit depth** — 1, 2, or 4 bits per channel (trade-off: capacity vs. distortion)
- **Netpbm I/O** — built-in PGM (P5) and PPM (P6) reader/writer, no image library needed
- **Arbitrary data** — hide strings, binary data, encryption keys, or any bytes
- **File-level API** — one-liner encode/decode for image files
- **Raw pixel API** — work directly with `Array{UInt8}` for integration with any image library
- **Zero dependencies** — pure Julia, no external packages
- **57 comprehensive tests** — encoding, decoding, distortion verification, Netpbm I/O, edge cases

## Installation

```julia
using Pkg
Pkg.add(url="https://github.com/bad-antics/Steganography.jl")
```

## Quick Start

### File-Level API

```julia
using Steganography

# Hide a message in an image
encode_file("cover.ppm", "stego.ppm", "top secret message")

# Extract the hidden message
message = decode_file("stego.ppm")
println(String(message))  # => "top secret message"
```

### Raw Pixel API

```julia
using Steganography

# Work with raw pixel data (any shape)
pixels = rand(UInt8, 100, 100, 3)  # 100×100 RGB image

# Check capacity
println(capacity(pixels))  # => bytes available for hiding

# Encode
stego = encode(pixels, "hidden data")

# Decode
recovered = String(decode(stego))
println(recovered)  # => "hidden data"
```

### Higher Capacity (2-bit or 4-bit LSB)

```julia
config = StegoConfig(bits_per_channel=2)  # 2× capacity, slightly more visible

stego = encode(pixels, large_data; config=config)
recovered = decode(stego; config=config)
```

## API Reference

### Core Functions

| Function | Description |
|----------|-------------|
| `encode(pixels, data; config)` | Return new array with data hidden in LSBs |
| `encode!(pixels, data; config)` | Encode data in-place |
| `decode(pixels; config)` | Extract hidden data from pixel LSBs |
| `capacity(pixels; config)` | Maximum bytes that can be hidden |

### File Functions

| Function | Description |
|----------|-------------|
| `encode_file(input, output, data; config)` | Read image, encode, write result |
| `decode_file(filepath; config)` | Read image, extract hidden data |
| `read_netpbm(filepath)` | Read PGM/PPM image |
| `write_netpbm(filepath, image_or_pixels)` | Write PGM/PPM image |

### Configuration

```julia
StegoConfig(bits_per_channel=1)  # 1, 2, or 4 bits per channel
```

| bits_per_channel | Max distortion per pixel | Relative capacity |
|:---:|:---:|:---:|
| 1 | ±1 | 1× |
| 2 | ±3 | 2× |
| 4 | ±15 | 4× |

## How It Works

1. **Length header**: A 4-byte big-endian payload length is prepended to the data
2. **Bit spreading**: Each payload byte is spread across `8/bpc` pixels by replacing LSBs
3. **Extraction**: LSBs are collected from pixels and reassembled into bytes

The encoding only modifies the least significant bit(s) of each pixel, making changes
imperceptible to the human eye (especially at 1-bit LSB).

## Supported Formats

- **PGM (P5)** — binary grayscale (8-bit)
- **PPM (P6)** — binary RGB color (24-bit)
- **Raw arrays** — any `Array{UInt8}` of any dimension

> **Tip**: Convert to/from PNG/JPEG using your preferred image library, then use the raw pixel API.

## License

MIT — see [LICENSE](LICENSE)
