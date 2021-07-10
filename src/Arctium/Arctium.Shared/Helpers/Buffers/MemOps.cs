using System;
using System.Collections.Generic;
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

        #region Unsafe

        public static unsafe void Memset(byte* ptr, byte value, long count)
        {
            for (int i = 0; i < count; i++) *(ptr + i) = value;
        }

        #endregion
    }
}
