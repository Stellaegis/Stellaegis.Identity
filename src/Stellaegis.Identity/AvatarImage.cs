using System.Buffers.Binary;
using System.Text;
using Stellaegis.Primitives;

namespace Stellaegis.Identity;

/// <summary>
/// The check of an avatar before it reaches the store: a PNG of 256 by 256 pixels, its structure and its checksums
/// sound, rebuilt from the chunks that draw the image and nothing else. A browser's canvas exports such a PNG
/// already; the check holds against an upload that did not come from it.
/// </summary>
/// <remarks>
/// Dropping every other chunk removes what a file carries besides the image — a text chunk, an EXIF profile, a
/// position — without decoding the pixels, and so without an image library. What is kept: <c>IHDR</c>, <c>PLTE</c>,
/// <c>tRNS</c> for the transparency, the <c>IDAT</c> chunks and <c>IEND</c>.
/// </remarks>
internal static class AvatarImage
{
    /// <summary>The side of an avatar, in pixels.</summary>
    public const int Side = 256;

    /// <summary>The largest file read before its chunks are dropped, in bytes.</summary>
    public const int MaxInputLength = 4 * AccountAvatar.MaxImageLength;

    private static readonly byte[] Signature = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
    private static readonly HashSet<string> Kept = new(StringComparer.Ordinal) { "IHDR", "PLTE", "tRNS", "IDAT", "IEND" };
    private static readonly uint[] CrcTable = BuildCrcTable();

    /// <summary>The image rebuilt from the chunks that draw it, or <see cref="IdentityErrors.InvalidAvatar"/>.</summary>
    public static Result<byte[]> Normalize(byte[]? file)
    {
        if (file is null || file.Length < Signature.Length || file.Length > MaxInputLength || !file.AsSpan(0, Signature.Length).SequenceEqual(Signature))
            return Result.Failure<byte[]>(IdentityErrors.InvalidAvatar);

        using var output = new MemoryStream(file.Length);
        output.Write(Signature);
        var position = Signature.Length;
        var first = true;
        var images = 0;
        while (position + 12 <= file.Length)
        {
            var length = BinaryPrimitives.ReadUInt32BigEndian(file.AsSpan(position, 4));
            if (length > int.MaxValue || position + 12 + (long)length > file.Length)
                return Result.Failure<byte[]>(IdentityErrors.InvalidAvatar);
            var chunk = file.AsSpan(position, 12 + (int)length);
            var type = Encoding.ASCII.GetString(chunk.Slice(4, 4));
            var data = chunk.Slice(8, (int)length);
            if (BinaryPrimitives.ReadUInt32BigEndian(chunk[^4..]) != Crc(chunk.Slice(4, 4 + (int)length)))
                return Result.Failure<byte[]>(IdentityErrors.InvalidAvatar);

            if (first && (type != "IHDR" || length != 13
                || BinaryPrimitives.ReadUInt32BigEndian(data) != Side || BinaryPrimitives.ReadUInt32BigEndian(data[4..]) != Side))
                return Result.Failure<byte[]>(IdentityErrors.InvalidAvatar);
            first = false;

            if (Kept.Contains(type))
                output.Write(chunk);
            if (type == "IDAT")
                images++;
            position += chunk.Length;
            if (type == "IEND")
            {
                return images > 0 && position == file.Length && output.Length <= AccountAvatar.MaxImageLength
                    ? Result.Success(output.ToArray())
                    : Result.Failure<byte[]>(IdentityErrors.InvalidAvatar);
            }
        }
        return Result.Failure<byte[]>(IdentityErrors.InvalidAvatar);
    }

    /// <summary>The CRC-32 of a chunk, over its type and its data, as the PNG specification defines it.</summary>
    internal static uint Crc(ReadOnlySpan<byte> bytes)
    {
        var crc = 0xffffffffu;
        foreach (var b in bytes)
            crc = CrcTable[(crc ^ b) & 0xff] ^ (crc >> 8);
        return crc ^ 0xffffffffu;
    }

    private static uint[] BuildCrcTable()
    {
        var table = new uint[256];
        for (var n = 0u; n < 256; n++)
        {
            var c = n;
            for (var k = 0; k < 8; k++)
                c = (c & 1) != 0 ? 0xedb88320u ^ (c >> 1) : c >> 1;
            table[n] = c;
        }
        return table;
    }
}
