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

        public int OutsideAppend(int length)
        {
            int offset = DataLength;
            ExtendIfNeededBuffer(length);
            DataLength += length;

            return offset;
        }

        public void TrimStart(int count)
        {
            if (count > DataLength) throw new Exception("internal: trying to trim more than datalength");

            int j = count;
            int i = 0;

            for (; i < count && j < DataLength; j++, i++)
            {
                Buffer[i] = Buffer[j];
            }

            DataLength -= count;
        }

        public void Append(params byte[] buffer) => Append(buffer, 0, buffer.Length);

        public void Append(byte[] buffer, int offset, int length)
        {
            ExtendIfNeededBuffer(length);

            MemCpy.Copy(buffer, offset, Buffer, DataLength, length);

            DataLength += length;
        }

        public void Reset()
        {
            DataLength = 0;
        }

        private void ExtendIfNeededBuffer(int dataToAppend)
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
    }
}
