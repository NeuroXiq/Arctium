using System;

namespace Arctium.Connection.Tls.Buffers
{
    ///<summary>Utility buffers to work with chunked data</summary>
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

        public void PrepareToAppend(int appendLength)
        {
            if (totalFreeSpace < appendLength)
            {
                ExtendBuffer(appendLength - totalFreeSpace + DataLength);
            }

            int appendFreeSpace = DataBuffer.Length - DataOffset - DataLength;

            if (appendFreeSpace < appendLength)
            {
                Buffer.BlockCopy(DataBuffer, DataOffset, DataBuffer, 0, DataLength);
            }
        }

        private void ExtendBuffer(int newSize)
        {
            byte[] newBuf = new byte[newSize];

            Buffer.BlockCopy(DataBuffer, DataOffset, newBuf, 0, DataLength);

            DataBuffer = newBuf;
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
