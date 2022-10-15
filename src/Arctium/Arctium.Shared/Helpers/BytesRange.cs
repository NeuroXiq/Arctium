namespace Arctium.Shared.Helpers
{
    /// <summary>
    /// Helper struct to store range of bytes (start offset and length) for byte array
    /// Have overload implicitly convert from byte[] array (0 offset, bytearray.length length)
    /// </summary>
    public struct BytesRange
    {
        public byte[] Buffer;
        public long Offset;
        public long Length;

        public BytesRange(byte[] buffer)
        {
            Buffer = buffer;
            Offset = 0;
            Length = buffer.Length;
        }

        public static implicit operator BytesRange(byte[] buffer) => new BytesRange(buffer);
    }
}
