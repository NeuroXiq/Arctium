using System.Runtime.CompilerServices;

namespace Arctium.DllGlobalShared.Helpers.Binary
{
    public static class BinConverter
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong ToULongLE(byte[] buffer, long offset)
        {
            return (ulong)
                (
                    ((ulong)buffer[offset + 7] <<  0) |
                    ((ulong)buffer[offset + 6] <<  8) |
                    ((ulong)buffer[offset + 5] << 16) |
                    ((ulong)buffer[offset + 4] << 24) |
                    ((ulong)buffer[offset + 3] << 32) |
                    ((ulong)buffer[offset + 2] << 40) |
                    ((ulong)buffer[offset + 1] << 48) |
                    ((ulong)buffer[offset + 0] << 56)
                );
        }


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong ToULongBE(byte[] buffer, long offset)
        {
            return (ulong)
                (
                    ((ulong)buffer[offset + 0] <<  0) |
                    ((ulong)buffer[offset + 1] <<  8) |
                    ((ulong)buffer[offset + 2] << 16) |
                    ((ulong)buffer[offset + 3] << 24) |
                    ((ulong)buffer[offset + 4] << 32) |
                    ((ulong)buffer[offset + 5] << 40) |
                    ((ulong)buffer[offset + 6] << 48) |
                    ((ulong)buffer[offset + 7] << 56) 
                );
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void IntToBE(byte[] buffer, long offset, uint value)
        {
            buffer[offset + 0] = (byte)((value >> 24) & 0xff);
            buffer[offset + 1] = (byte)((value >> 16) & 0xff);
            buffer[offset + 2] = (byte)((value >>  8) & 0xff);
            buffer[offset + 3] = (byte)((value >>  0) & 0xff);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void LongToBE(byte[] buffer, long offset, long value)
        {
            buffer[offset + 0] = (byte)((value >> 56) & (0xFF));
            buffer[offset + 1] = (byte)((value >> 48) & (0xFF));
            buffer[offset + 2] = (byte)((value >> 40) & (0xFF));
            buffer[offset + 3] = (byte)((value >> 32) & (0xFF));
            buffer[offset + 4] = (byte)((value >> 24) & (0xFF));
            buffer[offset + 5] = (byte)((value >> 16) & (0xFF));
            buffer[offset + 6] = (byte)((value >>  8) & (0xFF));
            buffer[offset + 7] = (byte)((value >>  0) & (0xFF));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ULongToBE(byte[] buffer, long offset, ulong value)
        {
            buffer[offset + 0] = (byte)((value >> 56) & (0xFF));
            buffer[offset + 1] = (byte)((value >> 48) & (0xFF));
            buffer[offset + 2] = (byte)((value >> 40) & (0xFF));
            buffer[offset + 3] = (byte)((value >> 32) & (0xFF));
            buffer[offset + 4] = (byte)((value >> 24) & (0xFF));
            buffer[offset + 5] = (byte)((value >> 16) & (0xFF));
            buffer[offset + 6] = (byte)((value >> 8) & (0xFF));
            buffer[offset + 7] = (byte)((value >> 0) & (0xFF));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint ToUIntBE(byte[] buffer, long offset)
        {
            uint result = (uint)
               (((uint)buffer[offset + 0] << 24) |
                ((uint)buffer[offset + 1] << 16) |
                ((uint)buffer[offset + 2] <<  8) |
                ((uint)buffer[offset + 3] <<  0));

            return result;
        }

        /// <summary>
        /// Converts byte array to the unsigned integer where array is represented as big-endian integer<br/>
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="length">Length of the bytes of the big-endiang integer</param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong ToULongBE(byte[] buffer, long offset, int length)
        {
            ulong value = 0;
            for (int i = 0; i < length; i++)
            {
                value |= (ulong)(buffer[offset + i]) << ((length - 1 - i) * 8);
            }

            return value;
        }

        /// <summary>
        /// Converts ulong value to the big-endian byte array where the most significant bytes with value 0 are removed
        /// </summary>
        /// <returns></returns>
        public static byte[] GetULtoBEMSTrim(ulong value)
        {
            int trimLen = 0;

            for (int i = 0; i < 8; i++)
            {
                if ((value >> (i * 8)) > 0) trimLen++;
                else break;
            }

            byte[] result = new byte[8 - trimLen];

            for (int i = trimLen; i < 8; i++)
            {
                result[i - trimLen] = (byte)(value >> (trimLen - i - 1));
            }

            return result;
        }

        //[MethodImpl(MethodImplOptions.AggressiveInlining)]
        //public static ulong ROTR(ulong value, int n)
        //{
        //    return ((value >> n) | (value << 64 - n));
        //}
    }
}
