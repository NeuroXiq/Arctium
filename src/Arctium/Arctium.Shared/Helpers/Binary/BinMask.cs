using System;
using System.Runtime.CompilerServices;

namespace Arctium.Shared.Helpers.Binary
{
    public static class BinMask
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static byte ByteUnset(params int[] bitsIndexes)
        {
            byte result = 0xff;
            for (int i = 0; i < bitsIndexes.Length; i++)
            {
                if (bitsIndexes[i] > 7 || bitsIndexes[i] < 0) throw new ArgumentException($"{i} index value is invalid for byte type");
                result -= (byte)(1 << bitsIndexes[i]);
            }
            return result;
        }


        public static byte ByteSet(params int[] bits)
        {
            byte result = 0;
            for (int i = 0; i < bits.Length; i++)
            {
                if (bits[i] > 7 || bits[i] < 0) throw new ArgumentException($"{i} index value is invalid for byte type");
                result |= (byte)(1 << bits[i]);
            }
            return result;
        }
    }
}
