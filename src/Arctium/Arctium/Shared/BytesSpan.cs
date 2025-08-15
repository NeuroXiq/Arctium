using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Shared
{
    public struct BytesSpan
    {
        public byte[] Buffer { get; private set; }
        public int Offset { get; private set; }
        public int Length { get; private set; }

        public byte this[int index]
        {
            get { ThrowIfOutOfRange(index); return Buffer[Offset + index]; }
            set { Buffer[index + Offset] = value; }
        }

        private void ThrowIfOutOfRange(int index)
        {
            if (index + Offset >= Length) throw new ArgumentOutOfRangeException("index if out of range");
        }

        public BytesSpan(byte[] buffer, int offset, int length)
        {
            
        }
    }
}
