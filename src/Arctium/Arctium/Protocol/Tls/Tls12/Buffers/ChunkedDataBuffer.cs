using System;

namespace Arctium.Protocol.Tls.Tls12.Buffers
{
    ///<summary>buffer helps working with chunked data</summary>
    class ChunkedDataBuffer
    {
        public int DataOffset { get; private set; }
        public int DataLength { get; set; }
        public byte[] DataBuffer { get; private set; }
        public int totalFreeSpace { get { return DataBuffer.Length - DataLength; } }

        public ChunkedDataBuffer()
        {
            DataBuffer = new byte[0];
            DataOffset = 0;
            DataLength = 0;
        }

        public void Append(byte[] buffer, int offset, int length)
        {
            PrepareToAppend(length);
            Buffer.BlockCopy(buffer, offset, DataBuffer, DataLength + DataOffset, length);
            DataLength += length;
        }

        private void PrepareToAppend(int appendLength)
        {
            if (totalFreeSpace < appendLength)
            {
                int extendLength = (appendLength + DataLength) - totalFreeSpace;
                ExtendBuffer(extendLength + DataBuffer.Length);
            }

            int appendFreeSpace = DataBuffer.Length - DataOffset - DataLength;

            if (appendFreeSpace < appendLength)
            {
                Buffer.BlockCopy(DataBuffer, DataOffset, DataBuffer, 0, DataLength);
                DataOffset = 0;
            }
        }

        private void ExtendBuffer(int newSize)
        {
            byte[] newBuf = new byte[newSize];

            Buffer.BlockCopy(DataBuffer, DataOffset, newBuf, 0, DataLength);

            DataBuffer = newBuf;
            DataOffset = 0;
        }

        public void Remove(int count)
        {
            if (count > DataLength)
                throw new InvalidOperationException("count exced current data length. Cannot remove more data than buffer contain");

            DataOffset += count;
            DataLength -= count;
        }
    }
}
