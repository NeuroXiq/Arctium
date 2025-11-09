using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Shared
{
    public class BytesCursor
    {
        public byte[] Buffer { get; private set; }
        public int EndOffset { get; private set; }
        public int StartOffset { get { return startOffset; } }
        public int Length => EndOffset - CurrentOffset + 1;
        public bool IsValidEnd => CurrentOffset == EndOffset + 1;
        public bool IsInvalidEnd => CurrentOffset > EndOffset + 1;
        public bool HasData => CurrentOffset <= EndOffset;

        public int CurrentOffset
        {
            get { return currentOffset; }
            set
            {
                if (EndOffset + 1 < value) throw new InvalidOperationException("new offset outside valid end");
                currentOffset = value; 
            }
        }

        private int startOffset;
        private int currentOffset;

        public byte this[int index]
        {
            get {  return Buffer[GetIndex(index)]; }
            set { Buffer[GetIndex(index)] = value; }
        }

        public void ShiftCurrentOffset(int relativePosition)
        {
            CurrentOffset += relativePosition;
        }

        private int GetIndex(int index)
        {
            ThrowIfOutOfRange(index);

            return CurrentOffset + index;
        }

        public BytesCursor(byte[] buffer, int offset, int length)
        {
            Buffer = buffer;
            startOffset = offset;
            EndOffset = offset + length - 1;
            CurrentOffset = offset;

            if (offset + length > buffer.Length) throw new ArgumentException("length exceed real buffer size");

            ThrowIfOutOfRange(0);
        }

        /// <summary>
        /// determines if has length from current offset
        /// </summary>
        /// <param name="length"></param>
        public bool HasLength(int length)
        {
            return EndOffset - CurrentOffset + 1 >= length;
        }

        private void ThrowIfOutOfRange(int index)
        {
            int i = CurrentOffset + index;

            if (i < 0 || i > EndOffset) throw new ArgumentException("(i < 0 || i > EndOffset)");
            if (index < 0) throw new ArgumentOutOfRangeException("index < 0");
        }

        public bool OffsetInStartEnd(int offset)
        {
            return StartOffset <= offset && EndOffset >= offset;
        }

        public override string ToString()
        {
            return $"C:{CurrentOffset} S:{StartOffset} E:{EndOffset} L:{Length} D:{(HasData ? Buffer[CurrentOffset] : '-'):X2}";
        }
    }
}
