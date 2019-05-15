using System;

namespace Arctium.Connection.Tls.Buffers
{
    ///<summary>This class facilitate work with fragmented data which must be compacted before processed</summary>
    class FragmentsBuffer
    {
        public int MaxSize { get; private set; }
        public int AvailableSpace { get { return MaxSize - DataLength; } }
        public int DataLength { get; private set; }
        public byte[] DataBuffer { get; private set; }
        public int DataOffset { get; private set; }


        ///<summary>creates new instance of the FragmentsBuffer class.</summary>
        ///<param name="maxSize">Maximum size of the internal buffer.</param>
        public FragmentsBuffer(int maxSize)
        {
            DataBuffer = new byte[4];
        }


        //
        // public methods
        //

        public void Append(byte[] buffer, int offset, int length)
        {
            if (AvailableSpace < length)
                throw new InvalidOperationException("Cannot append bytes because there is not enought free space in internall buffer");

            //buffer have enought free space to hold new data ?
            if (buffer.Length - DataLength > length)
            {
                ExtendBuffer(buffer.Length - DataLength + length);
                Buffer.BlockCopy(buffer, offset, DataBuffer, DataOffset + DataLength, length);
            }
            else
            {
                //can append bytes in this current state (no need to shift bytes to left) ? 
                if (DataOffset + DataLength + length < DataBuffer.Length)
                {
                    Buffer.BlockCopy(buffer, offset, DataBuffer, DataOffset + DataLength, length);
                }
                else
                {
                    //shift all bytes to the left 
                    Buffer.BlockCopy(DataBuffer, DataOffset, DataBuffer, 0, DataLength);

                    DataOffset = 0;

                    ///append bytes from method params
                    Buffer.BlockCopy(buffer, offset, DataBuffer, DataOffset + DataLength, length);
                }
            }

            DataLength += length;

        }

        private void ExtendBuffer(int newSize)
        {
            byte[] newBuf = new byte[newSize];

            Buffer.BlockCopy(DataBuffer, DataOffset, newBuf, 0, DataLength);
            DataOffset = 0;
            DataBuffer = newBuf;
        }

        public void MoveDataOffset(int count)
        {
            if (count > DataLength) throw new InvalidOperationException("count exceed available data");

            DataOffset += count;
            DataLength -= count;
        }

        public void HardExtendBuffer(int newSize)
        {
            if (newSize < MaxSize)
            {
                throw new InvalidOperationException("New buffer size cannot be smaller than current MaxSize");
            }

            MaxSize = newSize;
        }

        //
        // end of public methods
        //
    }
}
