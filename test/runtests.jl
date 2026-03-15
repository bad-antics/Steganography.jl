using Steganography
using Test

# Helper to create a simple PGM (P5) binary
function make_pgm(pixels::Matrix{UInt8})
    h, w = size(pixels)
    io = IOBuffer()
    write(io, "P5\n$w $h\n255\n")
    # Row-major order
    for r in 1:h
        for c in 1:w
            write(io, pixels[r, c])
        end
    end
    return take!(io)
end

# Helper to create a simple PPM (P6) binary
function make_ppm(pixels::Array{UInt8, 3})
    h, w, _ = size(pixels)
    io = IOBuffer()
    write(io, "P6\n$w $h\n255\n")
    for r in 1:h
        for c in 1:w
            write(io, pixels[r, c, 1], pixels[r, c, 2], pixels[r, c, 3])
        end
    end
    return take!(io)
end

@testset "Steganography.jl" begin

    @testset "Capacity Calculation" begin
        # 100 pixels, 1 bit per channel = 100 bits = 12 bytes - 4 header = 8 bytes
        pixels = zeros(UInt8, 100)
        @test capacity(pixels) == 8

        # 2 bits per channel = 200 bits = 25 bytes - 4 = 21
        @test capacity(pixels; config=StegoConfig(bits_per_channel=2)) == 21

        # 4 bits per channel = 400 bits = 50 bytes - 4 = 46
        @test capacity(pixels; config=StegoConfig(bits_per_channel=4)) == 46

        # 3D array (10×10×3 = 300 pixels)
        pixels3d = zeros(UInt8, 10, 10, 3)
        @test capacity(pixels3d) == 33  # 300/8 - 4 = 33

        # Too small
        tiny = zeros(UInt8, 10)
        @test capacity(tiny) == 0  # 10/8 = 1 byte total, minus 4 header = negative → 0
    end

    @testset "Basic Encode/Decode — 1-bit LSB" begin
        pixels = rand(UInt8, 500)
        message = "Hello, steganography!"
        
        stego = encode(pixels, message)
        @test length(stego) == length(pixels)
        @test stego !== pixels  # Different object
        
        recovered = decode(stego)
        @test String(recovered) == message
    end

    @testset "Encode/Decode — 2-bit LSB" begin
        config = StegoConfig(bits_per_channel=2)
        pixels = rand(UInt8, 200)
        message = "2-bit LSB test"
        
        stego = encode(pixels, message; config=config)
        recovered = decode(stego; config=config)
        @test String(recovered) == message
    end

    @testset "Encode/Decode — 4-bit LSB" begin
        config = StegoConfig(bits_per_channel=4)
        pixels = rand(UInt8, 200)
        message = "4-bit LSB test"
        
        stego = encode(pixels, message; config=config)
        recovered = decode(stego; config=config)
        @test String(recovered) == message
    end

    @testset "Binary Data" begin
        pixels = rand(UInt8, 1000)
        data = rand(UInt8, 50)
        
        stego = encode(pixels, data)
        recovered = decode(stego)
        @test recovered == data
    end

    @testset "In-place Encoding" begin
        pixels = rand(UInt8, 500)
        original = copy(pixels)
        message = "in-place test"
        
        encode!(pixels, message)
        @test pixels != original  # Modified in place
        
        recovered = decode(pixels)
        @test String(recovered) == message
    end

    @testset "Empty Data" begin
        pixels = rand(UInt8, 500)
        stego = encode(pixels, UInt8[])
        recovered = decode(stego)
        @test isempty(recovered)
    end

    @testset "Maximum Capacity" begin
        pixels = rand(UInt8, 200)
        cap = capacity(pixels)
        
        # Fill to exact capacity
        data = rand(UInt8, cap)
        stego = encode(pixels, data)
        recovered = decode(stego)
        @test recovered == data
        
        # Exceed capacity
        @test_throws ErrorException encode(pixels, rand(UInt8, cap + 1))
    end

    @testset "Pixel Distortion — 1-bit LSB" begin
        pixels = rand(UInt8, 500)
        message = "distortion test"
        
        stego = encode(pixels, message)
        
        # Maximum distortion should be 1 per pixel (LSB change)
        max_diff = maximum(abs.(Int.(stego) .- Int.(pixels)))
        @test max_diff <= 1
    end

    @testset "Pixel Distortion — 2-bit LSB" begin
        config = StegoConfig(bits_per_channel=2)
        pixels = rand(UInt8, 500)
        
        stego = encode(pixels, "test"; config=config)
        max_diff = maximum(abs.(Int.(stego) .- Int.(pixels)))
        @test max_diff <= 3  # 2 bits = max change of 3
    end

    @testset "Pixel Distortion — 4-bit LSB" begin
        config = StegoConfig(bits_per_channel=4)
        pixels = rand(UInt8, 500)
        
        stego = encode(pixels, "test"; config=config)
        max_diff = maximum(abs.(Int.(stego) .- Int.(pixels)))
        @test max_diff <= 15  # 4 bits = max change of 15
    end

    @testset "2D Array (Grayscale Image)" begin
        pixels = rand(UInt8, 50, 50)
        message = "grayscale test"
        
        stego = encode(pixels, message)
        @test size(stego) == size(pixels)
        
        recovered = decode(stego)
        @test String(recovered) == message
    end

    @testset "3D Array (Color Image)" begin
        pixels = rand(UInt8, 30, 30, 3)
        message = "RGB color test!"
        
        stego = encode(pixels, message)
        @test size(stego) == size(pixels)
        
        recovered = decode(stego)
        @test String(recovered) == message
    end

    @testset "Netpbm PGM Read/Write" begin
        # Create test PGM data
        pixels = rand(UInt8, 10, 10)
        pgm_data = make_pgm(pixels)
        
        # Write to temp file and read back
        tmpfile = tempname() * ".pgm"
        try
            write(tmpfile, pgm_data)
            img = read_netpbm(tmpfile)
            
            @test img.format == "P5"
            @test img.width == 10
            @test img.height == 10
            @test img.maxval == 255
            @test size(img.pixels) == (10, 10)
            @test img.pixels == pixels
        finally
            isfile(tmpfile) && rm(tmpfile)
        end
    end

    @testset "Netpbm PPM Read/Write" begin
        pixels = rand(UInt8, 8, 8, 3)
        ppm_data = make_ppm(pixels)
        
        tmpfile = tempname() * ".ppm"
        try
            write(tmpfile, ppm_data)
            img = read_netpbm(tmpfile)
            
            @test img.format == "P6"
            @test img.width == 8
            @test img.height == 8
            @test img.maxval == 255
            @test size(img.pixels) == (8, 8, 3)
            @test img.pixels == pixels
        finally
            isfile(tmpfile) && rm(tmpfile)
        end
    end

    @testset "Netpbm Roundtrip Write/Read" begin
        # PGM roundtrip
        pixels_gray = rand(UInt8, 12, 15)
        tmp_pgm = tempname() * ".pgm"
        try
            write_netpbm(tmp_pgm, pixels_gray)
            img = read_netpbm(tmp_pgm)
            @test img.pixels == pixels_gray
        finally
            isfile(tmp_pgm) && rm(tmp_pgm)
        end

        # PPM roundtrip
        pixels_color = rand(UInt8, 12, 15, 3)
        tmp_ppm = tempname() * ".ppm"
        try
            write_netpbm(tmp_ppm, pixels_color)
            img = read_netpbm(tmp_ppm)
            @test img.pixels == pixels_color
        finally
            isfile(tmp_ppm) && rm(tmp_ppm)
        end
    end

    @testset "File-Level Encode/Decode" begin
        # Create a cover image
        pixels = rand(UInt8, 50, 50, 3)
        ppm_data = make_ppm(pixels)
        
        cover = tempname() * ".ppm"
        stego = tempname() * ".ppm"
        
        try
            write(cover, ppm_data)
            message = "file-level steganography test!"
            
            encode_file(cover, stego, message)
            recovered = decode_file(stego)
            
            @test String(recovered) == message
            
            # Verify stego file is valid PPM
            img = read_netpbm(stego)
            @test img.format == "P6"
            @test img.width == 50
            @test img.height == 50
        finally
            isfile(cover) && rm(cover)
            isfile(stego) && rm(stego)
        end
    end

    @testset "File-Level with Binary Data" begin
        pixels = rand(UInt8, 40, 40)
        pgm_data = make_pgm(pixels)
        
        cover = tempname() * ".pgm"
        stego = tempname() * ".pgm"
        
        try
            write(cover, pgm_data)
            data = rand(UInt8, 100)
            
            encode_file(cover, stego, data)
            recovered = decode_file(stego)
            
            @test recovered == data
        finally
            isfile(cover) && rm(cover)
            isfile(stego) && rm(stego)
        end
    end

    @testset "Netpbm with Comments" begin
        # PGM with comments in header
        io = IOBuffer()
        write(io, "P5\n# This is a comment\n4 4\n# Another comment\n255\n")
        write(io, rand(UInt8, 16))
        data = take!(io)
        
        tmpfile = tempname() * ".pgm"
        try
            write(tmpfile, data)
            img = read_netpbm(tmpfile)
            @test img.format == "P5"
            @test img.width == 4
            @test img.height == 4
        finally
            isfile(tmpfile) && rm(tmpfile)
        end
    end

    @testset "Config Validation" begin
        @test_throws ErrorException StegoConfig(bits_per_channel=3)
        @test_throws ErrorException StegoConfig(bits_per_channel=0)
        @test_throws ErrorException StegoConfig(bits_per_channel=8)
        
        # Valid configs
        @test StegoConfig(bits_per_channel=1).bits_per_channel == 1
        @test StegoConfig(bits_per_channel=2).bits_per_channel == 2
        @test StegoConfig(bits_per_channel=4).bits_per_channel == 4
    end

    @testset "Wrong Config Decode Fails Gracefully" begin
        pixels = rand(UInt8, 1000)
        config1 = StegoConfig(bits_per_channel=1)
        config2 = StegoConfig(bits_per_channel=2)
        
        stego = encode(pixels, "test message"; config=config1)
        
        # Decoding with wrong config should either error or return wrong data
        # (it won't match the original message)
        try
            wrong = decode(stego; config=config2)
            @test String(wrong) != "test message"
        catch e
            @test e isa ErrorException  # Invalid payload length
        end
    end

    @testset "Repeated Encode Overwrites" begin
        pixels = rand(UInt8, 1000)
        
        stego1 = encode(pixels, "first message")
        stego2 = encode(stego1, "second message")
        
        recovered = decode(stego2)
        @test String(recovered) == "second message"
    end

    @testset "All Zeros Carrier" begin
        pixels = zeros(UInt8, 500)
        message = "hidden in zeros"
        
        stego = encode(pixels, message)
        recovered = decode(stego)
        @test String(recovered) == message
    end

    @testset "All 0xFF Carrier" begin
        pixels = fill(UInt8(0xff), 500)
        message = "hidden in 0xFF"
        
        stego = encode(pixels, message)
        recovered = decode(stego)
        @test String(recovered) == message
    end

    @testset "Unicode Message" begin
        pixels = rand(UInt8, 2000)
        message = "Hello 🔐 世界 🌍 Шифр"
        
        stego = encode(pixels, message)
        recovered = decode(stego)
        @test String(recovered) == message
    end

    @testset "Long Message" begin
        pixels = rand(UInt8, 100_000)
        message = repeat("A", capacity(pixels))
        
        stego = encode(pixels, message)
        recovered = decode(stego)
        @test String(recovered) == message
    end

end
