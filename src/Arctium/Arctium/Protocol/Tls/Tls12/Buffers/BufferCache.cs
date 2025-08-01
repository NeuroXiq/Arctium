using System.IO;

namespace Arctium.Protocol.Tls.Tls12.Buffers
{
    class BufferCache
    {
        public int Size { get; private set; }
        public byte[] Buffer { get; private set; }
        public int DataLength { get; private set; }

        public BufferCache(int maxSize)
        {
            Size = maxSize;
            Buffer = new byte[maxSize];
            DataLength = 0;

        }

        ///<summary>Try to read bytes to fill entire empty space in buffer</summary>
        public int WriteFrom(Stream stream)
        {
            int readed = stream.Read(Buffer, DataLength, Size - DataLength);
            DataLength += readed;

            return readed;
        }

        ///<summary>Fill all available empty space</summary>
        public int WriteFrom(byte[] buffer, int offset, int length)
        {

            int copyCount = -1;
            int availableSpace = Size - length;

            if (length <= availableSpace) copyCount = length;
            else copyCount = availableSpace;

            for (int i = 0; i < copyCount; i++)
            {
                Buffer[DataLength + i] = buffer[i + offset];
            }

            DataLength += copyCount;

            return copyCount;
        }

        ///<summary>Removes all bytes from start position and shift all remaining to new empty space</summary>
        public void TrimStart(int count)
        {
            for (int i = count; i < DataLength; i++)
            {
                Buffer[i - count] = Buffer[i];
            }

            DataLength = DataLength - count;
        }

    }
}
