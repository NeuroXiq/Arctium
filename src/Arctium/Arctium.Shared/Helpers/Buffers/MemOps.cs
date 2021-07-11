using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;

namespace Arctium.Shared.Helpers.Buffers
{
    public static class MemOps
    {
        /// <summary>
        /// Compares two byte arrays
        /// </summary>
        /// <param name="mem1"></param>
        /// <param name="mem2"></param>
        /// <returns></returns>
        public static bool Memcmp(byte[] mem1, byte[] mem2)
        {
            if (mem1.Length == mem2.Length)
            {
                for (int i = 0; i < mem1.Length; i++)
                {
                    if (mem1[i] != mem2[i])
                    {
                        return false;
                    }
                }

                return true;
            }

            return false;
        }

        public static void Memset(ulong[] array, long offset, long count, ulong value)
        {
            for(long i = offset; i < offset + count; i++) 
            {
                array[i] = value;
            }
        }

        /// <summary>
        /// Xor source with xorWith. Results are stored in source
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Xor4ULong(ulong[] source, long ioffset, ulong[] xorWith, ulong xoffset)
        {
            source[ioffset + 0] ^= xorWith[xoffset + 0];
            source[ioffset + 1] ^= xorWith[xoffset + 1];
            source[ioffset + 2] ^= xorWith[xoffset + 2];
            source[ioffset + 3] ^= xorWith[xoffset + 3];
        }

        #region Unsafe

        public static unsafe void Memset(byte* ptr, byte value, long count)
        {
            for (int i = 0; i < count; i++) *(ptr + i) = value;
        }

        #endregion
    }
}
