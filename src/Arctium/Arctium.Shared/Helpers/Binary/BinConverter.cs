using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Arctium.Shared.Helpers.Binary
{



    /// <summary>
    /// All methods contains attribute to be forced inline.
    /// LE,BE suffixed means little-endian,big-endian byte ordering. <br/>
    /// Conversions to byte array starts with ToBytesXX where xx is byte ordering (LE/BE) <br/>
    /// Conversion to type from byte array starts with ToYYYYYXX where Y is a type name
    /// and XX is a byte ordering (LE/BE)
    /// </summary>
    public unsafe static class BinConverter
    {

        // 
        // MANAGED CODE START
        //

        #region Managed 


        // managed
        //

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint ToUIntLE(byte[] buffer, long offset)
        {
            return (uint)(
                (buffer[offset + 0] << 0) |
                (buffer[offset + 1] << 8) |
                (buffer[offset + 2] << 16) |
                (buffer[offset + 3] << 24));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ushort ToUShortBE(byte[] buffer, long offset)
        {
            return (ushort)((buffer[offset] << 8) | buffer[offset + 1]);
        }


        /// <summary>
        /// Converts 4 bytes to unsigned integer, 
        /// conversion assumes that bytes are stored
        /// in bit-endian order (BE)
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <returns></returns>
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
        public static ulong ToULongBE(byte[] buffer, long offset)
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
        public static ulong ToULongLE(byte[] buffer, long offset)
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

        public static bool[] ToBooleanArray(byte flagsArray)
        {
            bool[] flags = new bool[8];

            for (int j = 0; j < 8; j++)
            {
                flags[j] = (flagsArray & (1 << j)) > 0;
            }

            return flags;
        }

        /*
         * From value to byte array
         *  
         */

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ToBytesBE(byte[] buffer, long offset, ulong value)
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
        public static void ToBytesBE(byte[] buffer, long offset, uint value)
        {
            buffer[offset + 0] = (byte)((value >> 24) & 0xff);
            buffer[offset + 1] = (byte)((value >> 16) & 0xff);
            buffer[offset + 2] = (byte)((value >> 8) & 0xff);
            buffer[offset + 3] = (byte)((value >> 0) & 0xff);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ToBytesBE(byte[] buffer, long offset, long value)
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
        public static byte[] ToBytesBE(ulong value)
        {
            byte[] result = new byte[8];
            ToBytesBE(result, 0, value);

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


        #endregion

        //
        // MANAGED CODE END
        //



        //
        // UNMANAGED CODE START
        //

        #region Unmanaged

        #region byte array -> value 


        public static ulong ToULongLE(byte* buffer)
        {
            return (ulong)(
                ((ulong)buffer[7] << 56) |
                ((ulong)buffer[6] << 48) |
                ((ulong)buffer[5] << 40) |
                ((ulong)buffer[4] << 32) |
                ((ulong)buffer[3] << 24) |
                ((ulong)buffer[2] << 16) |
                ((ulong)buffer[1] << 8) |
                ((ulong)buffer[0] << 0));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong ToULongBE(byte* buffer)
        {
            return (ulong)(
                ((ulong)buffer[0] << 56) |
                ((ulong)buffer[1] << 48) |
                ((ulong)buffer[2] << 40) |
                ((ulong)buffer[3] << 32) |
                ((ulong)buffer[4] << 24) |
                ((ulong)buffer[5] << 16) |
                ((ulong)buffer[6] <<  8) |
                ((ulong)buffer[7] <<  0));
        }

        /// <summary>
        /// Converts bytes to uint in little-endian order
        /// </summary>
        /// <param name="buffer">Pointer to the buffer</param>
        /// <returns>bytes converted to uint</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint ToUIntLE(byte* buffer)
        {
            return (uint)(
                (buffer[0] << 0) |
                (buffer[1] << 8) |
                (buffer[2] << 16) |
                (buffer[3] << 24));
        }

        /// <summary>
        /// Converts 4 bytes to unsigned integer, 
        /// conversion assumes that bytes are stored
        /// in bit-endian order (BE)
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint ToUIntBE(byte* buffer, long offset)
        {
            uint result = (uint)
               (((uint)buffer[offset + 0] << 24) |
                ((uint)buffer[offset + 1] << 16) |
                ((uint)buffer[offset + 2] << 8) |
                ((uint)buffer[offset + 3] << 0));

            return result;
        }

        #endregion

        #region Unsafe value -> byte array

        /// <summary>
        /// Converts unsigned integer input to byte array in Little-endian format.
        /// Most significant byte is writed to output[3]
        /// </summary>
        /// <param name="value">Value to convert to by array</param>
        /// <param name="output">Output buffer where bytes will be writed. Length must be at least 4 bytes</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ToBytesLE(uint value, byte* outputArray)
        {
            outputArray[0] = (byte)(value >> 0);
            outputArray[1] = (byte)(value >> 8);
            outputArray[2] = (byte)(value >> 16);
            outputArray[3] = (byte)(value >> 24);
        }

        #endregion

        #endregion

        //
        // UNMANAGED CODE END
        //


        //
        // Other uncommon
        //

        public static string ToHexString(byte[] input) => ToHexString(input, 0, input.Length);

        public static string ToHexString(byte[] input, int offset, int length)
        {
            string r = "";
            for (int i = 0; i < length; i++)
            {
                r += String.Format("{0:X2}", input[i + offset]);
            }

            return r;
        }

        public static string ToStringHex(int value)
        {
            return String.Format("0x{0:X8}", value);
        }

        public static string ToStringHex(uint value)
        {
            return String.Format("0x{0:X8}", value);
        }

        public static string ToStringHex(byte value)
        {
            return String.Format("0x{0:X2}", value);
        }

        public static string ToStringHex(ushort value)
        {
            return String.Format("0x{0:X4}", value);
        }


        public static byte[] FromString(string hexString, bool autotrim)
        {
            hexString = hexString.Trim();
            hexString = hexString.Replace(" ", "");
            hexString = hexString.Replace("\r", "");
            hexString = hexString.Replace("\n", "");

            return FromString(hexString);
        }

        /// <summary>
        /// Converts string to byte array. Stream must contain valid 
        /// hexadecimal values, must be multiply of 2 and must not contain any delimiters (space etc.).
        /// Only 0-9A-F allowed
        /// </summary>
        /// <param name="hexString"></param>
        /// <returns></returns>
        public static byte[] FromString(string hexString)
        {
            if (hexString.Length % 2 != 0)
                throw new ArgumentException("String value must be valid hex string (multiply of 2)");

            int length = hexString.Length / 2;

            byte[] parsed = new byte[length];
            for (int i = 0; i < hexString.Length; i += 2)
            {
                parsed[i / 2] = byte.Parse(hexString.Substring(i,2), System.Globalization.NumberStyles.HexNumber);
            }

            return parsed;
        }

        public static byte[] FromString(string s, string byteDelimiter)
        {
            string[] bytes = s.Split(byteDelimiter);
            byte[] parsed = new byte[bytes.Length];

            for (int i = 0; i < bytes.Length; i++)
            {
                parsed[i] = byte.Parse(bytes[i], System.Globalization.NumberStyles.HexNumber);
            }

            return parsed;
        }
    }
}
