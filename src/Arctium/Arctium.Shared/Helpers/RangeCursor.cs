using System;

namespace Arctium.Shared.Helpers
{
    public struct RangeCursor
    {
        private int currentPosition;
        public bool OnMaxPosition { get { return currentPosition == MaxPosition; } }
        public int CurrentPosition
        {
            get { return currentPosition; }
            set { ThrowIfOutside(value); currentPosition = value; }
        }
        public int MaxPosition { get; private set; }

        public RangeCursor(int currentPosition, int maxPosition)
        {
            this.currentPosition = currentPosition;
            MaxPosition = maxPosition;

            CurrentPosition = currentPosition;
        }

        public void Move(int shift)
        {
            ThrowIfShiftOutside(shift);
            
            checked
            {
                CurrentPosition += shift;
            }
        }

        public void ThrowIfOutside(int newPosition)
        {
            if (newPosition > MaxPosition)
                throw new InvalidOperationException("cursor outside");
        }


        public void ThrowIfShiftOutside(int shift) => ThrowIfOutside(currentPosition + shift);

        public static implicit operator int(RangeCursor cursor) => cursor.CurrentPosition;
        public static RangeCursor operator +(RangeCursor cursor, int value) { cursor.Move(value); return cursor; }
        public static RangeCursor operator ++(RangeCursor cursor) { cursor.Move(1); return cursor; }

        public void ChangeMaxPosition(int newMaxPosition)
        {
            MaxPosition = newMaxPosition;
            ThrowIfOutside(currentPosition);
        }
    }
}
