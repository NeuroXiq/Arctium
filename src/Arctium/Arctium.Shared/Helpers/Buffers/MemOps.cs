using System;
using System.Collections.Generic;
using System.Text;

namespace Arctium.Shared.Helpers.Buffers
{
    public static class MemOps
    {
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

        #region Unsafe

        public static unsafe void Memset(byte* ptr, byte value, long count)
        {
            for (int i = 0; i < count; i++) *(ptr + i) = value;
        }

        #endregion
    }
}
