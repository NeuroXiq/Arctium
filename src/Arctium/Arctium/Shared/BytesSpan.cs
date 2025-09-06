using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Shared
{
    public class BytesSpan
    {
        public byte[] Buffer { get; private set; }
        public int Offset { get; set; }
        public int Length { get; private set; }

        public byte this[int index]
        {
            get {  return Buffer[GetIndex(index)]; }
            set { Buffer[index + Offset] = value; }
        }

        public void ShiftOffset(int relativePosition)
        {
            Offset += relativePosition;
        }

        public int GetIndex(int index)
        {
            ThrowIfOutOfRange(index);

            return Offset + index;
        }

        public BytesSpan(byte[] buffer, int offset, int length)
        {
            Buffer = buffer;
            Length = length;
            Offset = offset;

            if (offset + length > buffer.Length) throw new ArgumentException("length exceed real buffer size");

            ThrowIfOutOfRange(0);
        }

        private void ThrowIfOutOfRange(int index)
        {
            if (Offset < 0 || Offset >= Buffer.Length) throw new ArgumentException("Offset < 0 || Offset >= Buffer.Length");
            if (index < 0) throw new ArgumentOutOfRangeException("negative index");
            if (index + Offset >= Length) throw new ArgumentOutOfRangeException("index if out of range");
        }
    }
}
