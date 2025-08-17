namespace Arctium.Shared
{
    // todo: remove this

    /// <summary>
    /// Helper struct to store range of bytes (start offset and length) for byte array.
    /// Have overload implicitly convert from byte[] array (0 offset, bytearray.length length).
    /// Implicit overload means that 'byte[]' can be used directly to assign/as method parameter instead of creating instance of this struct
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

        public BytesRange(byte[] buffer, long offset, long length)
        {
            Buffer = buffer;
            Offset = offset;
            Length = length;
        }

        public static implicit operator BytesRange(byte[] buffer) => new BytesRange(buffer);
    }
}
