using System;
using System.Runtime.CompilerServices;

namespace Arctium.DllGlobalShared.Helpers.Binary
{
    public static class BinConverter
    {
        /*
         * From byte array to number
         */

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint ToUIntBE(byte[] buffer, long offset)
        {
            uint result = (uint)
               (((uint)buffer[offset + 0] << 24) |
                ((uint)buffer[offset + 1] << 16) |
                ((uint)buffer[offset + 2] << 8) |
                ((uint)buffer[offset + 3] << 0));

            return result;
        }


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong ToULongLE(byte[] buffer, long offset)
        {
            return (ulong)
                (
                    ((ulong)buffer[offset + 7] << 0) |
                    ((ulong)buffer[offset + 6] << 8) |
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
                    ((ulong)buffer[offset + 0] << 0) |
                    ((ulong)buffer[offset + 1] << 8) |
                    ((ulong)buffer[offset + 2] << 16) |
                    ((ulong)buffer[offset + 3] << 24) |
                    ((ulong)buffer[offset + 4] << 32) |
                    ((ulong)buffer[offset + 5] << 40) |
                    ((ulong)buffer[offset + 6] << 48) |
                    ((ulong)buffer[offset + 7] << 56)
                );
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong ToULongLE(byte[] buffer, long offset, long length)
        {
            if (length < 0 || length > 8) throw new ArgumentException("length 0-8");

            ulong result = 0;
            int shift = 0;
            for (long i = offset + length - 1; i >= offset; i--)
            {
                result |= ((ulong)buffer[i] << (shift));
                shift += 8;
            }

            return result;
        }

        /// <summary>
        /// Converts byte array to the unsigned integer where array is represented as big-endian integer
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="length">Count of the bytes representing a big-endiang integer</param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong ToULongBE(byte[] buffer, long offset, int length)
        {
            if (length > 8 || length < 1)
                throw new ArgumentException($"length in bytes of the ulong value must be in range 1-8");

            ulong value = 0;
            for (int i = 0; i < length; i++)
            {
                value |= (ulong)(buffer[offset + i]) << ((length - 1 - i) * 8);
            }

            return value;
        }

        /*
         * From number to byte array
         *  
         */

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void GetBytesBE(byte[] buffer, long offset, ulong value)
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
        public static void GetBytesBE(byte[] buffer, long offset, uint value)
        {
            buffer[offset + 0] = (byte)((value >> 24) & 0xff);
            buffer[offset + 1] = (byte)((value >> 16) & 0xff);
            buffer[offset + 2] = (byte)((value >> 8) & 0xff);
            buffer[offset + 3] = (byte)((value >> 0) & 0xff);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void GetBytesBE(byte[] buffer, long offset, long value)
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
        public static byte[] GetBytesBE(ulong value)
        {
            byte[] result = new byte[8];
            GetBytesBE(result, 0, value);

            return result;
        }

        /// <summary>
        /// Converts ulong value to the Big-Endian byte array where the Most Significant bytes with value 0 are Trimmed
        /// </summary>
        /// <returns></returns>
        public static byte[] GetBytesTrimToEmptyLE(ulong value)
        {
            int length = 0;

            for (int i = 0; i < 8; i++)
            {
                if (((value >> (i * 8)) & 0xFF) != 0) length++;
                else break;
            }

            byte[] result = new byte[length];

            for (int i = 0; i < length; i++)
            {
                result[length - i - 1] = (byte)(value >> (i * 8));
            }

            return result;
        }

        public static byte[] GetBytesTrimToLastLE(ulong value)
        {
            int length = 1;

            for (int i = 1; i < 8; i++)
            {
                if (((value >> (i * 8)) & 0xFF) != 0) length++;
                else break;
            }

            byte[] result = new byte[length];

            for (int i = 0; i < length; i++)
            {
                result[length - i - 1] = (byte)(value >> (i * 8));
            }

            return result;
        }
    }
}
