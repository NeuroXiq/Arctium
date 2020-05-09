using System;
using System.Runtime.CompilerServices;

namespace Arctium.Shared.Helpers.Binary
{
    public static class BinOps
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint ROR(uint v, int r)
        {
            return (v >> r) | (v << (32 - r));
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
            return (value << r) | (value >> (32 - r));
        }
    }
}
