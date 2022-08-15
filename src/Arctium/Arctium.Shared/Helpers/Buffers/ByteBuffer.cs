using System;

namespace Arctium.Shared.Helpers.Buffers
{
    public class ByteBuffer
    {
        public byte[] Buffer { get; private set; }
        public int DataLength { get; set; }

        int freeSpace { get { return Buffer.Length - DataLength; } }

        public ByteBuffer()
        {
            Buffer = new byte[1024];
        }

        public void Append(byte[] buffer) => Append(buffer, 0, buffer.Length);

        public void Append(byte[] buffer, int offset, int length)
        {
            if (Buffer.Length - DataLength < length) ExtendBuffer(DataLength + length);

            MemCpy.Copy(buffer, offset, Buffer, DataLength, length);

            DataLength += length;
        }

        public void Reset()
        {
            DataLength = 0;
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
