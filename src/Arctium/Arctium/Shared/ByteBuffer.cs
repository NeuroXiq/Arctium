using System;

namespace Arctium.Shared
{
    public class ByteBuffer
    {
        public byte[] Buffer { get; private set; }
        public int DataLength { get; private set; }

        int freeSpace { get { return Buffer.Length - DataLength; } }

        public ByteBuffer()
        {
            Buffer = new byte[1024];
        }

        public byte this[int index]
        {
            get
            {
                CheckIndex(index);
                return Buffer[index];
            }
            set
            {
                CheckIndex(index);
                Buffer[index] = value;
            }
        }

        private void CheckIndex(int index)
        {
            if (DataLength <= index || index < 0)
                throw new ArgumentException("index out of range");
        }

        /// <summary>
        /// Asserts buffer size (extends if neeed) that allow append 'length' bytes to if
        /// returns index where data must be appended
        /// </summary>
        /// <param name="length"></param>
        /// <returns>data length before appending bytes (this offset can be used to start writing to</returns>
        public int AllocEnd(int length)
        {
            int offset = DataLength;
            ExtendIfNeeded(length);
            DataLength += length;

            return offset;
        }

        public void TrimStart(int count)
        {
            if (count > DataLength) throw new Exception("internal: trying to trim more than datalength");

            // int j = count;
            // int i = 0;

            for (int i = 0; i < DataLength - count; i++)
            {
                Buffer[i] = Buffer[i + count];
            }

            DataLength -= count;
        }

        public void Append(Memory<byte> buffer) => Append(buffer.Span, 0, buffer.Length);

        public void Append(Span<byte> buffer, int offset, int length)
        {
            ExtendIfNeeded(length);
            MemCpy.Copy(buffer, offset, Buffer, DataLength, length);

            DataLength += length;
        }

        public void Append(params byte[] items) => Append(new Span<byte>(items), 0, items.Length);

        public void Append(Span<byte> buffer) => Append(buffer, 0, buffer.Length);

        public void Append(byte[] buffer, int offset, int length) => Append(new Span<byte>(buffer), offset, length);

        public void Reset()
        {
            DataLength = 0;
        }

        public void ExtendIfNeeded(int dataToAppend)
        {
            int newLength = dataToAppend + DataLength;

            if (newLength <= Buffer.Length) return;

            int extendedLen = Buffer.Length;

            while (extendedLen < newLength)
            {
                extendedLen <<= 1;
            }

            byte[] newBuffer = new byte[extendedLen];

            MemCpy.Copy(Buffer, 0, newBuffer, 0, DataLength);

            Buffer = newBuffer;
        }

        public void AllocStart(int prependLength)
        {
            ExtendIfNeeded(prependLength);
            int shiftRight = DataLength;
            DataLength += prependLength;

            if (DataLength == prependLength) return;

            // move data to free beginning of the buffer (shift data right to make free 'predendLength' at buffer start)
            for (int i = 0; i < shiftRight; i++)
            {
                Buffer[DataLength - 1 - i] = Buffer[DataLength - prependLength - 1 - i];
            }
        }
    }
}
