using System;

namespace Arctium.Shared.Helpers.Buffers
{
    public class ByteBuffer
    {
        public byte[] Buffer { get; private set; }
        public int DataLength { get; set; }

        public ByteBuffer()
        {
            Buffer = new byte[1024];
        }

        public void Append(byte[] buffer, int offset, int length)
        {
            if (Buffer.Length - DataLength < length) ExtendBuffer(DataLength + length);

            MemCpy.Copy(buffer, offset, Buffer, DataLength, length);

            DataLength += length;
        }

        private void ExtendBuffer(int newLength)
        {
            int extendedLen = Buffer.Length;

            while (extendedLen < newLength)
            {
                extendedLen <<= 1;
            }

            byte[] newBuffer = new byte[extendedLen];

            MemCpy.Copy(Buffer, 0, newBuffer, 0, DataLength);

            Buffer = newBuffer;
        }
    }
}
