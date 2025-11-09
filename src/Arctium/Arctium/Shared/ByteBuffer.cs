using System;

namespace Arctium.Shared
{
    public class ByteBuffer
    {
        public byte[] Buffer { get; private set; }
        
        /// <summary>
        /// real data length appended/allocated in buffer, means total buffer size, always is <= Buffer.Length
        /// </summary>
        public int Length { get; private set; }

        int freeSpace { get { return Buffer.Length - Length; } }

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
            if (Length <= index || index < 0)
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
            int offset = Length;
            ExtendIfNeeded(length);
            Length += length;

            return offset;
        }

        public void TrimStart(int count)
        {
            if (count > Length) throw new Exception("internal: trying to trim more than datalength");

            // int j = count;
            // int i = 0;

            for (int i = 0; i < Length - count; i++)
            {
                Buffer[i] = Buffer[i + count];
            }

            Length -= count;
        }

        public void Append(Memory<byte> buffer) => Append(buffer.Span, 0, buffer.Length);

        public void Append(Span<byte> buffer, int offset, int length)
        {
            ExtendIfNeeded(length);
            MemCpy.Copy(buffer, offset, Buffer, Length, length);

            Length += length;
        }

        public void Append(params byte[] items) => Append(new Span<byte>(items), 0, items.Length);

        public void Append(Span<byte> buffer) => Append(buffer, 0, buffer.Length);

        public void Append(byte[] buffer, int offset, int length) => Append(new Span<byte>(buffer), offset, length);

        public void Reset()
        {
            Length = 0;
        }

        public void ExtendIfNeeded(int dataToAppend)
        {
            int newLength = dataToAppend + Length;

            if (newLength <= Buffer.Length) return;

            int extendedLen = Buffer.Length;

            while (extendedLen < newLength)
            {
                extendedLen <<= 1;
            }

            byte[] newBuffer = new byte[extendedLen];

            MemCpy.Copy(Buffer, 0, newBuffer, 0, Length);

            Buffer = newBuffer;
        }

        public void AllocStart(int prependLength)
        {
            ExtendIfNeeded(prependLength);
            int shiftRight = Length;
            Length += prependLength;

            if (Length == prependLength) return;

            // move data to free beginning of the buffer (shift data right to make free 'predendLength' at buffer start)
            for (int i = 0; i < shiftRight; i++)
            {
                Buffer[Length - 1 - i] = Buffer[Length - prependLength - 1 - i];
            }
        }
    }
}
