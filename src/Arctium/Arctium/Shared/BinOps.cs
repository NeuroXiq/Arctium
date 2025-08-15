using System;
using System.Runtime.CompilerServices;

namespace Arctium.Shared
{
    /// <summary>
    /// Binary Operations
    /// </summary>
    public static class BinOps
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint ROR(uint v, int r)
        {
            return v >> r | v << 32 - r;
        }

        /// <summary>
        /// Rotates left 32-bit integer
        /// </summary>
        /// <param name="value">Value to rotate</param>
        /// <param name="r">Rotation</param>
        /// <returns>Result of the rotation</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint ROL(uint value, int r)
        {
            return value << r | value >> 32 - r;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        ///<summary>
        /// Rotates right 64-bit value
        ///</summary>
        public static ulong ROR(ulong value, int r) { return value >> r | value << 64 - r; }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong ROL(ulong value, int r) { return value << r | value >> 64 - r; }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong RevertBytes(ulong value)
        {
            return
                (value & 0xFF00000000000000) >> 56 |
                (value & 0x00FF000000000000) >> 40 |
                (value & 0x0000FF0000000000) >> 16 |
                (value & 0x000000FF00000000) >> 08 |
                (value & 0x00000000FF000000) << 08 |
                (value & 0x0000000000FF0000) << 16 |
                (value & 0x000000000000FF00) << 40 |
                (value & 0x00000000000000FF) << 56;
        }


        /// <summary>
        /// Reverse bits in input value. That means that bit on position (bits zero indexed) 63 appears on position
        /// 0, bit on position 2 appears on 62 etc.
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public static ulong BitReflect(ulong value)
        {
            ulong result = 0;

            for (int i = 0; i < 64; i++)
            {
                if ((value & (ulong)1 << i) != 0)
                {
                    result |= (ulong)1 << 63 - i;
                }
            }

            return result;
        }

        /// <summary>
        /// Reverse bits in input value. That means that bit on position (bits zero indexed) 2 appears on position
        /// 5, bit on position 1 appears on 6 etc.
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public static byte BitReflect(byte value)
        {
            byte result = 0;

            for (int i = 0; i < 8; i++)
            {
                if ((value & 1 << i) != 0)
                {
                    result |= (byte)(1 << 7 - i);
                }
            }

            return result;
        }
    }
}
