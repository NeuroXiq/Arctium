using System;
using System.Runtime.CompilerServices;

namespace Arctium.Shared.Helpers.Buffers
{
    /// <summary>
    /// Performs some common mapping from blocks of types to other types.
    /// Optimized, expanded versions of mapping. This conversions operatates on 
    /// arrays of values e.g. convert 8 uint array to 32 byte array
    /// </summary>
    public static unsafe class MemMap
    {
        #region Unsafe

        public static void ToBytes1UIntBE(uint v, byte* output, long outOffset)
        {
            output[outOffset + 0] = (byte)((v >> 24) & 0xFF);
            output[outOffset + 1] = (byte)((v >> 16) & 0xFF);
            output[outOffset + 2] = (byte)((v >> 08) & 0xFF);
            output[outOffset + 3] = (byte)((v >> 00) & 0xFF);
        }

        public static uint ToNewUInt4BytesBE(byte* input, long inOffset)
        {
            uint r = 0;
            r |= (uint)((input[inOffset + 0]) << 24);
            r |= (uint)((input[inOffset + 1]) << 16);
            r |= (uint)((input[inOffset + 2]) << 08);
            r |= (uint)((input[inOffset + 3]) << 00);

            return r;
        }

        public static void ToUInt16BytesBE(byte* src, long srcOffset, uint* dst, long dstOffset)
        {
            long so = srcOffset;

            for (int i = 0; i < 4; i++)
            {
                dst[i + dstOffset] =
                    (uint)(src[so + 0] << 24) |
                    (uint)(src[so + 1] << 16) |
                    (uint)(src[so + 2] << 08) |
                    (uint)(src[so + 3] << 00);

                so += 4;
            }
        }


        /// <summary>
        /// Converts array of 4 unsigned integers to byte array in little-endian format
        /// </summary>
        /// <param name="array">input array to convert</param>
        /// <param name="output">output bytes array</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ToBytes4UIntLE(uint* array, byte* output)
        {
            output[0] = (byte)(array[0] >> 0);
            output[1] = (byte)(array[0] >> 8);
            output[2] = (byte)(array[0] >> 16);
            output[3] = (byte)(array[0] >> 24);

            output[4] = (byte)(array[1] >> 0);
            output[5] = (byte)(array[1] >> 8);
            output[6] = (byte)(array[1] >> 16);
            output[7] = (byte)(array[1] >> 24);

            output[8] = (byte)(array[2] >> 0);
            output[9] = (byte)(array[2] >> 8);
            output[10] = (byte)(array[2] >> 16);
            output[11] = (byte)(array[2] >> 24);

            output[12] = (byte)(array[3] >> 0);
            output[13] = (byte)(array[3] >> 8);
            output[14] = (byte)(array[3] >> 16);
            output[15] = (byte)(array[3] >> 24);
        }

        /// <summary>
        /// Converts array of the unsigned integers to byte array.
        /// Bytes of the uint values are mapped to the result array
        /// in a big-endian order
        /// </summary>
        /// <param name="uintPtr">Pointer for the uint array</param>
        /// <param name="length">length of the uint array (length = 2 means 8 bytes of memory)</param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static byte[] ToByteArrayBE(uint* uintPtr, int length)
        {
            byte[] buf = new byte[length * 4];

            for (int i = 0, j = 0; i < length; i++, j += 4)
            {
                buf[j] = (byte)(uintPtr[i] >> 24);
                buf[j + 1] = (byte)(uintPtr[i] >> 16);
                buf[j + 2] = (byte)(uintPtr[i] >> 8);
                buf[j + 3] = (byte)(uintPtr[i] >> 0);
            }

            return buf;
        }

        /// <summary>
        /// Converts array of the unsigned integers to byte array in little endian order
        /// </summary>
        /// <param name="input"></param>
        /// <param name="length">Length of the input array (count of unsigned integers)</param>
        /// <returns></returns>
        public static byte[] ToByteArrayLE(uint* input, int length)
        {
            byte[] result = new byte[length * 4];

            for (int i = 0, j = 0; i < length; i++, j += 4)
            {
                result[j + 0] = (byte)(input[i] >> 0);
                result[j + 1] = (byte)(input[i] >> 8);
                result[j + 2] = (byte)(input[i] >> 16);
                result[j + 3] = (byte)(input[i] >> 24);
            }

            return result;
        }

        /// <summary>
        /// Converts array of 16 bytes to array of 4 uint where each Uint is mapped 
        /// to little-endian fromat. Means that input[0] is least significant byte of 
        /// output[0] uint value
        /// </summary>
        /// <param name="input"></param>
        /// <param name="p"></param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ToUInt16BytesLE(byte* input, uint* output)
        {
            output[0] = (uint)input[0] << 0;
            output[0] |= (uint)input[1] << 8;
            output[0] |= (uint)input[2] << 16;
            output[0] |= (uint)input[3] << 24;

            output[1] = (uint)input[4] << 0;
            output[1] |= (uint)input[5] << 8;
            output[1] |= (uint)input[6] << 16;
            output[1] |= (uint)input[7] << 24;

            output[2] = (uint)input[8] << 0;
            output[2] |= (uint)input[9] << 8;
            output[2] |= (uint)input[10] << 16;
            output[2] |= (uint)input[11] << 24;

            output[3] = (uint)input[12] << 0;
            output[3] |= (uint)input[13] << 8;
            output[3] |= (uint)input[14] << 16;
            output[3] |= (uint)input[15] << 24;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ToUInt64BytesBE(byte* input, long inputOffset, uint* output, long outputOffset)
        {
            long o = outputOffset, i = inputOffset;

            for (int k = 0; k < 4; k++)
            {
                output[0 + o] = (uint)input[3 + i] << 0;
                output[0 + o] |= (uint)input[2 + i] << 8;
                output[0 + o] |= (uint)input[1 + i] << 16;
                output[0 + o] |= (uint)input[0 + i] << 24;

                output[1 + o] = (uint)input[7 + i] << 0;
                output[1 + o] |= (uint)input[6 + i] << 8;
                output[1 + o] |= (uint)input[5 + i] << 16;
                output[1 + o] |= (uint)input[4 + i] << 24;

                output[2 + o] = (uint)input[11 + i] << 0;
                output[2 + o] |= (uint)input[10 + i] << 8;
                output[2 + o] |= (uint)input[9 + i] << 16;
                output[2 + o] |= (uint)input[8 + i] << 24;

                output[3 + o] = (uint)input[15 + i] << 0;
                output[3 + o] |= (uint)input[14 + i] << 8;
                output[3 + o] |= (uint)input[13 + i] << 16;
                output[3 + o] |= (uint)input[12 + i] << 24;

                o += 4;
                i += 16;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ToUInt64BytesBE(byte[] input, long inputOffset, uint[] output, long outputOffset)
        {
            long o = outputOffset, i = inputOffset;

            for (int k = 0; k < 4; k++)
            {
                output[0 + o] = (uint)input[3 + i] << 0;
                output[0 + o] |= (uint)input[2 + i] << 8;
                output[0 + o] |= (uint)input[1 + i] << 16;
                output[0 + o] |= (uint)input[0 + i] << 24;

                output[1 + o] = (uint)input[7 + i] << 0;
                output[1 + o] |= (uint)input[6 + i] << 8;
                output[1 + o] |= (uint)input[5 + i] << 16;
                output[1 + o] |= (uint)input[4 + i] << 24;

                output[2 + o] = (uint)input[11 + i] << 0;
                output[2 + o] |= (uint)input[10 + i] << 8;
                output[2 + o] |= (uint)input[9 + i] << 16;
                output[2 + o] |= (uint)input[8 + i] << 24;

                output[3 + o] = (uint)input[15 + i] << 0;
                output[3 + o] |= (uint)input[14 + i] << 8;
                output[3 + o] |= (uint)input[13 + i] << 16;
                output[3 + o] |= (uint)input[12 + i] << 24;

                o += 4;
                i += 16;
            }
        }

        /// <summary>
        /// Converts 32 bytes to 8 uint values where input bytes 
        /// are intepreted as little-endia 4-bytes integers
        /// </summary>
        /// <param name=""></param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ToUInt32BytesLE(byte* input, uint* output)
        {
            output[0] = (uint)input[0];
            output[0] |= (uint)(input[1] << 8);
            output[0] |= (uint)(input[2] << 16);
            output[0] |= (uint)(input[3] << 24);

            output[1] = (uint)input[4];
            output[1] |= (uint)(input[5] << 8);
            output[1] |= (uint)(input[6] << 16);
            output[1] |= (uint)(input[7] << 24);

            output[2] = (uint)input[8];
            output[2] |= (uint)(input[9] << 8);
            output[2] |= (uint)(input[10] << 16);
            output[2] |= (uint)(input[11] << 24);

            output[3] = (uint)input[12];
            output[3] |= (uint)(input[13] << 8);
            output[3] |= (uint)(input[14] << 16);
            output[3] |= (uint)(input[15] << 24);

            output[4] = (uint)input[16];
            output[4] |= (uint)(input[17] << 8);
            output[4] |= (uint)(input[18] << 16);
            output[4] |= (uint)(input[19] << 24);

            output[5] = (uint)input[20];
            output[5] |= (uint)(input[21] << 8);
            output[5] |= (uint)(input[22] << 16);
            output[5] |= (uint)(input[23] << 24);

            output[6] = (uint)input[24];
            output[6] |= (uint)(input[25] << 8);
            output[6] |= (uint)(input[26] << 16);
            output[6] |= (uint)(input[27] << 24);

            output[7] = (uint)input[28];
            output[7] |= (uint)(input[29] << 8);
            output[7] |= (uint)(input[30] << 16);
            output[7] |= (uint)(input[31] << 24);
        }


        /// <summary>
        /// Maps 64 bytes to 16 uint values where bytes are interpreted as
        /// litte-endian integers. Input[0] becomes least significat byte of output[0]
        /// Input[7] is most significat byte of output[1] etc...
        /// </summary>
        /// <param name="input">Input memory to map</param>
        /// <param name="output">uint output buffer of length 16</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ToUInt64BytesLE(byte* input, uint* output)
        {
            output[0] = (uint)input[0 + 0] << 0;
            output[0] |= (uint)input[0 + 1] << 8;
            output[0] |= (uint)input[0 + 2] << 16;
            output[0] |= (uint)input[0 + 3] << 24;

            output[1] = (uint)input[4 + 0] << 0;
            output[1] |= (uint)input[4 + 1] << 8;
            output[1] |= (uint)input[4 + 2] << 16;
            output[1] |= (uint)input[4 + 3] << 24;

            output[2] = (uint)input[8 + 0] << 0;
            output[2] |= (uint)input[8 + 1] << 8;
            output[2] |= (uint)input[8 + 2] << 16;
            output[2] |= (uint)input[8 + 3] << 24;

            output[3] = (uint)input[12 + 0] << 0;
            output[3] |= (uint)input[12 + 1] << 8;
            output[3] |= (uint)input[12 + 2] << 16;
            output[3] |= (uint)input[12 + 3] << 24;

            output[4] = (uint)input[16 + 0] << 0;
            output[4] |= (uint)input[16 + 1] << 8;
            output[4] |= (uint)input[16 + 2] << 16;
            output[4] |= (uint)input[16 + 3] << 24;

            output[5] = (uint)input[20 + 0] << 0;
            output[5] |= (uint)input[20 + 1] << 8;
            output[5] |= (uint)input[20 + 2] << 16;
            output[5] |= (uint)input[20 + 3] << 24;

            output[6] = (uint)input[24 + 0] << 0;
            output[6] |= (uint)input[24 + 1] << 8;
            output[6] |= (uint)input[24 + 2] << 16;
            output[6] |= (uint)input[24 + 3] << 24;

            output[7] = (uint)input[28 + 0] << 0;
            output[7] |= (uint)input[28 + 1] << 8;
            output[7] |= (uint)input[28 + 2] << 16;
            output[7] |= (uint)input[28 + 3] << 24;

            output[8] = (uint)input[32 + 0] << 0;
            output[8] |= (uint)input[32 + 1] << 8;
            output[8] |= (uint)input[32 + 2] << 16;
            output[8] |= (uint)input[32 + 3] << 24;

            output[9] = (uint)input[36 + 0] << 0;
            output[9] |= (uint)input[36 + 1] << 8;
            output[9] |= (uint)input[36 + 2] << 16;
            output[9] |= (uint)input[36 + 3] << 24;

            output[10] = (uint)input[40 + 0] << 0;
            output[10] |= (uint)input[40 + 1] << 8;
            output[10] |= (uint)input[40 + 2] << 16;
            output[10] |= (uint)input[40 + 3] << 24;

            output[11] = (uint)input[44 + 0] << 0;
            output[11] |= (uint)input[44 + 1] << 8;
            output[11] |= (uint)input[44 + 2] << 16;
            output[11] |= (uint)input[44 + 3] << 24;

            output[12] = (uint)input[48 + 0] << 0;
            output[12] |= (uint)input[48 + 1] << 8;
            output[12] |= (uint)input[48 + 2] << 16;
            output[12] |= (uint)input[48 + 3] << 24;

            output[13] = (uint)input[52 + 0] << 0;
            output[13] |= (uint)input[52 + 1] << 8;
            output[13] |= (uint)input[52 + 2] << 16;
            output[13] |= (uint)input[52 + 3] << 24;

            output[14] = (uint)input[56 + 0] << 0;
            output[14] |= (uint)input[56 + 1] << 8;
            output[14] |= (uint)input[56 + 2] << 16;
            output[14] |= (uint)input[56 + 3] << 24;

            output[15] = (uint)input[60 + 0] << 0;
            output[15] |= (uint)input[60 + 1] << 8;
            output[15] |= (uint)input[60 + 2] << 16;
            output[15] |= (uint)input[60 + 3] << 24;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ToUInt64BytesLE(byte[] input, long inputOffset, uint[] output, long outputOffset)
        {
            long i = inputOffset, o = outputOffset;

            output[o + 0] = (uint)input[i + 0 + 0] << 0;
            output[o + 0] |= (uint)input[i + 0 + 1] << 8;
            output[o + 0] |= (uint)input[i + 0 + 2] << 16;
            output[o + 0] |= (uint)input[i + 0 + 3] << 24;

            output[o + 1] = (uint)input[i + 4 + 0] << 0;
            output[o + 1] |= (uint)input[i + 4 + 1] << 8;
            output[o + 1] |= (uint)input[i + 4 + 2] << 16;
            output[o + 1] |= (uint)input[i + 4 + 3] << 24;

            output[o + 2] = (uint)input[i + 8 + 0] << 0;
            output[o + 2] |= (uint)input[i + 8 + 1] << 8;
            output[o + 2] |= (uint)input[i + 8 + 2] << 16;
            output[o + 2] |= (uint)input[i + 8 + 3] << 24;

            output[o + 3] = (uint)input[i + 12 + 0] << 0;
            output[o + 3] |= (uint)input[i + 12 + 1] << 8;
            output[o + 3] |= (uint)input[i + 12 + 2] << 16;
            output[o + 3] |= (uint)input[i + 12 + 3] << 24;

            output[o + 4] = (uint)input[i + 16 + 0] << 0;
            output[o + 4] |= (uint)input[i + 16 + 1] << 8;
            output[o + 4] |= (uint)input[i + 16 + 2] << 16;
            output[o + 4] |= (uint)input[i + 16 + 3] << 24;

            output[o + 5] = (uint)input[i + 20 + 0] << 0;
            output[o + 5] |= (uint)input[i + 20 + 1] << 8;
            output[o + 5] |= (uint)input[i + 20 + 2] << 16;
            output[o + 5] |= (uint)input[i + 20 + 3] << 24;

            output[o + 6] = (uint)input[i + 24 + 0] << 0;
            output[o + 6] |= (uint)input[i + 24 + 1] << 8;
            output[o + 6] |= (uint)input[i + 24 + 2] << 16;
            output[o + 6] |= (uint)input[i + 24 + 3] << 24;

            output[o + 7] = (uint)input[i + 28 + 0] << 0;
            output[o + 7] |= (uint)input[i + 28 + 1] << 8;
            output[o + 7] |= (uint)input[i + 28 + 2] << 16;
            output[o + 7] |= (uint)input[i + 28 + 3] << 24;

            output[o + 8] = (uint)input[i + 32 + 0] << 0;
            output[o + 8] |= (uint)input[i + 32 + 1] << 8;
            output[o + 8] |= (uint)input[i + 32 + 2] << 16;
            output[o + 8] |= (uint)input[i + 32 + 3] << 24;

            output[o + 9] = (uint)input[i + 36 + 0] << 0;
            output[o + 9] |= (uint)input[i + 36 + 1] << 8;
            output[o + 9] |= (uint)input[i + 36 + 2] << 16;
            output[o + 9] |= (uint)input[i + 36 + 3] << 24;

            output[o + 10] = (uint)input[i + 40 + 0] << 0;
            output[o + 10] |= (uint)input[i + 40 + 1] << 8;
            output[o + 10] |= (uint)input[i + 40 + 2] << 16;
            output[o + 10] |= (uint)input[i + 40 + 3] << 24;

            output[o + 11] = (uint)input[i + 44 + 0] << 0;
            output[o + 11] |= (uint)input[i + 44 + 1] << 8;
            output[o + 11] |= (uint)input[i + 44 + 2] << 16;
            output[o + 11] |= (uint)input[i + 44 + 3] << 24;

            output[o + 12] = (uint)input[i + 48 + 0] << 0;
            output[o + 12] |= (uint)input[i + 48 + 1] << 8;
            output[o + 12] |= (uint)input[i + 48 + 2] << 16;
            output[o + 12] |= (uint)input[i + 48 + 3] << 24;

            output[o + 13] = (uint)input[i + 52 + 0] << 0;
            output[o + 13] |= (uint)input[i + 52 + 1] << 8;
            output[o + 13] |= (uint)input[i + 52 + 2] << 16;
            output[o + 13] |= (uint)input[i + 52 + 3] << 24;

            output[o + 14] = (uint)input[i + 56 + 0] << 0;
            output[o + 14] |= (uint)input[i + 56 + 1] << 8;
            output[o + 14] |= (uint)input[i + 56 + 2] << 16;
            output[o + 14] |= (uint)input[i + 56 + 3] << 24;

            output[o + 15] = (uint)input[i + 60 + 0] << 0;
            output[o + 15] |= (uint)input[i + 60 + 1] << 8;
            output[o + 15] |= (uint)input[i + 60 + 2] << 16;
            output[o + 15] |= (uint)input[i + 60 + 3] << 24;
        }


        /// <summary>
        /// Maps 128 bytes to 16 ulong value where byte are interpreted as 
        /// little-endian integers. src[0] becomes least significant byte of 
        /// dst[0] value.
        /// </summary>
        /// <param name="src">128 - byte array to map</param>
        /// <param name="dst">16 - ulong array</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ToULong128BytesLE(byte* src, ulong* dst)
        {
            dst[0] = (ulong)(src[0]);
            dst[0] |= ((ulong)src[1]) << 8;
            dst[0] |= ((ulong)src[2]) << 16;
            dst[0] |= ((ulong)src[3]) << 24;
            dst[0] |= ((ulong)src[4]) << 32;
            dst[0] |= ((ulong)src[5]) << 40;
            dst[0] |= ((ulong)src[6]) << 48;
            dst[0] |= ((ulong)src[7]) << 56;

            dst[1] = (ulong)(src[8]);
            dst[1] |= ((ulong)src[9]) << 8;
            dst[1] |= ((ulong)src[10]) << 16;
            dst[1] |= ((ulong)src[11]) << 24;
            dst[1] |= ((ulong)src[12]) << 32;
            dst[1] |= ((ulong)src[13]) << 40;
            dst[1] |= ((ulong)src[14]) << 48;
            dst[1] |= ((ulong)src[15]) << 56;

            dst[2] = (ulong)(src[16]);
            dst[2] |= ((ulong)src[17]) << 8;
            dst[2] |= ((ulong)src[18]) << 16;
            dst[2] |= ((ulong)src[19]) << 24;
            dst[2] |= ((ulong)src[20]) << 32;
            dst[2] |= ((ulong)src[21]) << 40;
            dst[2] |= ((ulong)src[22]) << 48;
            dst[2] |= ((ulong)src[23]) << 56;

            dst[3] = (ulong)(src[24]);
            dst[3] |= ((ulong)src[25]) << 8;
            dst[3] |= ((ulong)src[26]) << 16;
            dst[3] |= ((ulong)src[27]) << 24;
            dst[3] |= ((ulong)src[28]) << 32;
            dst[3] |= ((ulong)src[29]) << 40;
            dst[3] |= ((ulong)src[30]) << 48;
            dst[3] |= ((ulong)src[31]) << 56;

            dst[4] = (ulong)(src[32]);
            dst[4] |= ((ulong)src[33]) << 8;
            dst[4] |= ((ulong)src[34]) << 16;
            dst[4] |= ((ulong)src[35]) << 24;
            dst[4] |= ((ulong)src[36]) << 32;
            dst[4] |= ((ulong)src[37]) << 40;
            dst[4] |= ((ulong)src[38]) << 48;
            dst[4] |= ((ulong)src[39]) << 56;

            dst[5] = (ulong)(src[40]);
            dst[5] |= ((ulong)src[41]) << 8;
            dst[5] |= ((ulong)src[42]) << 16;
            dst[5] |= ((ulong)src[43]) << 24;
            dst[5] |= ((ulong)src[44]) << 32;
            dst[5] |= ((ulong)src[45]) << 40;
            dst[5] |= ((ulong)src[46]) << 48;
            dst[5] |= ((ulong)src[47]) << 56;

            dst[6] = (ulong)(src[48]);
            dst[6] |= ((ulong)src[49]) << 8;
            dst[6] |= ((ulong)src[50]) << 16;
            dst[6] |= ((ulong)src[51]) << 24;
            dst[6] |= ((ulong)src[52]) << 32;
            dst[6] |= ((ulong)src[53]) << 40;
            dst[6] |= ((ulong)src[54]) << 48;
            dst[6] |= ((ulong)src[55]) << 56;

            dst[7] = (ulong)(src[56]);
            dst[7] |= ((ulong)src[57]) << 8;
            dst[7] |= ((ulong)src[58]) << 16;
            dst[7] |= ((ulong)src[59]) << 24;
            dst[7] |= ((ulong)src[60]) << 32;
            dst[7] |= ((ulong)src[61]) << 40;
            dst[7] |= ((ulong)src[62]) << 48;
            dst[7] |= ((ulong)src[63]) << 56;

            dst[8] = (ulong)(src[64]);
            dst[8] |= ((ulong)src[65]) << 8;
            dst[8] |= ((ulong)src[66]) << 16;
            dst[8] |= ((ulong)src[67]) << 24;
            dst[8] |= ((ulong)src[68]) << 32;
            dst[8] |= ((ulong)src[69]) << 40;
            dst[8] |= ((ulong)src[70]) << 48;
            dst[8] |= ((ulong)src[71]) << 56;

            dst[9] = (ulong)(src[72]);
            dst[9] |= ((ulong)src[73]) << 8;
            dst[9] |= ((ulong)src[74]) << 16;
            dst[9] |= ((ulong)src[75]) << 24;
            dst[9] |= ((ulong)src[76]) << 32;
            dst[9] |= ((ulong)src[77]) << 40;
            dst[9] |= ((ulong)src[78]) << 48;
            dst[9] |= ((ulong)src[79]) << 56;

            dst[10] = (ulong)(src[80]);
            dst[10] |= ((ulong)src[81]) << 8;
            dst[10] |= ((ulong)src[82]) << 16;
            dst[10] |= ((ulong)src[83]) << 24;
            dst[10] |= ((ulong)src[84]) << 32;
            dst[10] |= ((ulong)src[85]) << 40;
            dst[10] |= ((ulong)src[86]) << 48;
            dst[10] |= ((ulong)src[87]) << 56;

            dst[11] = (ulong)(src[88]);
            dst[11] |= ((ulong)src[89]) << 8;
            dst[11] |= ((ulong)src[90]) << 16;
            dst[11] |= ((ulong)src[91]) << 24;
            dst[11] |= ((ulong)src[92]) << 32;
            dst[11] |= ((ulong)src[93]) << 40;
            dst[11] |= ((ulong)src[94]) << 48;
            dst[11] |= ((ulong)src[95]) << 56;

            dst[12] = (ulong)(src[96]);
            dst[12] |= ((ulong)src[97]) << 8;
            dst[12] |= ((ulong)src[98]) << 16;
            dst[12] |= ((ulong)src[99]) << 24;
            dst[12] |= ((ulong)src[100]) << 32;
            dst[12] |= ((ulong)src[101]) << 40;
            dst[12] |= ((ulong)src[102]) << 48;
            dst[12] |= ((ulong)src[103]) << 56;

            dst[13] = (ulong)(src[104]);
            dst[13] |= ((ulong)src[105]) << 8;
            dst[13] |= ((ulong)src[106]) << 16;
            dst[13] |= ((ulong)src[107]) << 24;
            dst[13] |= ((ulong)src[108]) << 32;
            dst[13] |= ((ulong)src[109]) << 40;
            dst[13] |= ((ulong)src[110]) << 48;
            dst[13] |= ((ulong)src[111]) << 56;

            dst[14] = (ulong)(src[112]);
            dst[14] |= ((ulong)src[113]) << 8;
            dst[14] |= ((ulong)src[114]) << 16;
            dst[14] |= ((ulong)src[115]) << 24;
            dst[14] |= ((ulong)src[116]) << 32;
            dst[14] |= ((ulong)src[117]) << 40;
            dst[14] |= ((ulong)src[118]) << 48;
            dst[14] |= ((ulong)src[119]) << 56;

            dst[15] = (ulong)(src[120]);
            dst[15] |= ((ulong)src[121]) << 8;
            dst[15] |= ((ulong)src[122]) << 16;
            dst[15] |= ((ulong)src[123]) << 24;
            dst[15] |= ((ulong)src[124]) << 32;
            dst[15] |= ((ulong)src[125]) << 40;
            dst[15] |= ((ulong)src[126]) << 48;
            dst[15] |= ((ulong)src[127]) << 56;
        }

        #endregion


        #region managed
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static byte[] ToByteArrayLE(ulong[] src)
        {
            byte[] dst = new byte[src.Length * 8];

            for (int i = 0; i < src.Length; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    dst[(i * 8) + j] = (byte)(src[i] >> 8 * j);
                }
            }

            return dst;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static byte[] ToNewByteArrayLE(uint[] input, int length)
        {
            byte[] result = new byte[length * 4];

            for (int i = 0, j = 0; i < length; i++, j += 4)
            {
                result[j + 0] = (byte)(input[i] >> 0);
                result[j + 1] = (byte)(input[i] >> 8);
                result[j + 2] = (byte)(input[i] >> 16);
                result[j + 3] = (byte)(input[i] >> 24);
            }

            return result;
        }

        ///<summary>
        ///
        ///<summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ToULongNBytesLE(byte[] input, long inputOffset, ulong[] output, long outputOffset, long outputULongCount)
        {
            for (long i = inputOffset, j = outputOffset; i < (8 * outputULongCount) + inputOffset; i += 8, j++)
            {
                output[j] = (ulong)(
                       (ulong)input[i + 7] << 56 |
                       (ulong)input[i + 6] << 48 |
                       (ulong)input[i + 5] << 40 |
                       (ulong)input[i + 4] << 32 |
                       (ulong)input[i + 3] << 24 |
                       (ulong)input[i + 2] << 16 |
                       (ulong)input[i + 1] << 8 |
                       (ulong)input[i + 0] << 0);

            }
        }


        ///<summary>
        /// Converts array of 32 bytes to array of two ulong's. Bytes in input byte array are interpreted in Little Endian order
        ///<summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ToULong32BytesLE(byte[] input, ulong[] output)
        {
            ToULong32BytesLE(input, 0, output, 0);
        }

        ///<summary>
        /// Converts array of 32 bytes to array of two ulong's. Bytes in input byte array are interpreted in Little Endian order
        ///<summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ToULong32BytesLE(byte[] input, long inputOffset, ulong[] output, long outputOffset)
        {
            output[outputOffset] = (ulong)(
                    (ulong)input[inputOffset + 7] << 56 |
                    (ulong)input[inputOffset + 6] << 48 |
                    (ulong)input[inputOffset + 5] << 40 |
                    (ulong)input[inputOffset + 4] << 32 |
                    (ulong)input[inputOffset + 3] << 24 |
                    (ulong)input[inputOffset + 2] << 16 |
                    (ulong)input[inputOffset + 1] << 8 |
                    (ulong)input[inputOffset + 0] << 0);

            output[outputOffset + 1] = (ulong)(
                   (ulong)input[inputOffset + 8 + 7] << 56 |
                   (ulong)input[inputOffset + 8 + 6] << 48 |
                   (ulong)input[inputOffset + 8 + 5] << 40 |
                   (ulong)input[inputOffset + 8 + 4] << 32 |
                   (ulong)input[inputOffset + 8 + 3] << 24 |
                   (ulong)input[inputOffset + 8 + 2] << 16 |
                   (ulong)input[inputOffset + 8 + 1] << 8 |
                   (ulong)input[inputOffset + 8 + 0] << 0);

            output[outputOffset + 2] = (ulong)(
                    (ulong)input[inputOffset + 16 + 7] << 56 |
                    (ulong)input[inputOffset + 16 + 6] << 48 |
                    (ulong)input[inputOffset + 16 + 5] << 40 |
                    (ulong)input[inputOffset + 16 + 4] << 32 |
                    (ulong)input[inputOffset + 16 + 3] << 24 |
                    (ulong)input[inputOffset + 16 + 2] << 16 |
                    (ulong)input[inputOffset + 16 + 1] << 8 |
                    (ulong)input[inputOffset + 16 + 0] << 0);

            output[outputOffset + 3] = (ulong)(
                   (ulong)input[inputOffset + 24 + 7] << 56 |
                   (ulong)input[inputOffset + 24 + 6] << 48 |
                   (ulong)input[inputOffset + 24 + 5] << 40 |
                   (ulong)input[inputOffset + 24 + 4] << 32 |
                   (ulong)input[inputOffset + 24 + 3] << 24 |
                   (ulong)input[inputOffset + 24 + 2] << 16 |
                   (ulong)input[inputOffset + 24 + 1] << 8 |
                   (ulong)input[inputOffset + 24 + 0] << 0);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong ToULong8BytesLE(byte[] input, long inputOffset)
        {
            return (ulong)(
                    (ulong)input[inputOffset + 7] << 56 |
                    (ulong)input[inputOffset + 6] << 48 |
                    (ulong)input[inputOffset + 5] << 40 |
                    (ulong)input[inputOffset + 4] << 32 |
                    (ulong)input[inputOffset + 3] << 24 |
                    (ulong)input[inputOffset + 2] << 16 |
                    (ulong)input[inputOffset + 1] << 8 |
                    (ulong)input[inputOffset + 0] << 0);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ToBytes4ULongLE(ulong[] input, long inputOffset, byte[] output, long outputOffset)
        {
            output[outputOffset + 0 + 0] = (byte)((input[inputOffset + 0] >> 0) & 0xFF);
            output[outputOffset + 0 + 1] = (byte)((input[inputOffset + 0] >> 8) & 0xFF);
            output[outputOffset + 0 + 2] = (byte)((input[inputOffset + 0] >> 16) & 0xFF);
            output[outputOffset + 0 + 3] = (byte)((input[inputOffset + 0] >> 24) & 0xFF);
            output[outputOffset + 0 + 4] = (byte)((input[inputOffset + 0] >> 32) & 0xFF);
            output[outputOffset + 0 + 5] = (byte)((input[inputOffset + 0] >> 40) & 0xFF);
            output[outputOffset + 0 + 6] = (byte)((input[inputOffset + 0] >> 48) & 0xFF);
            output[outputOffset + 0 + 7] = (byte)((input[inputOffset + 0] >> 56) & 0xFF);

            output[outputOffset + 8 + 0] = (byte)((input[inputOffset + 1] >> 0) & 0xFF);
            output[outputOffset + 8 + 1] = (byte)((input[inputOffset + 1] >> 8) & 0xFF);
            output[outputOffset + 8 + 2] = (byte)((input[inputOffset + 1] >> 16) & 0xFF);
            output[outputOffset + 8 + 3] = (byte)((input[inputOffset + 1] >> 24) & 0xFF);
            output[outputOffset + 8 + 4] = (byte)((input[inputOffset + 1] >> 32) & 0xFF);
            output[outputOffset + 8 + 5] = (byte)((input[inputOffset + 1] >> 40) & 0xFF);
            output[outputOffset + 8 + 6] = (byte)((input[inputOffset + 1] >> 48) & 0xFF);
            output[outputOffset + 8 + 7] = (byte)((input[inputOffset + 1] >> 56) & 0xFF);

            output[outputOffset + 16 + 0] = (byte)((input[inputOffset + 2] >> 0) & 0xFF);
            output[outputOffset + 16 + 1] = (byte)((input[inputOffset + 2] >> 8) & 0xFF);
            output[outputOffset + 16 + 2] = (byte)((input[inputOffset + 2] >> 16) & 0xFF);
            output[outputOffset + 16 + 3] = (byte)((input[inputOffset + 2] >> 24) & 0xFF);
            output[outputOffset + 16 + 4] = (byte)((input[inputOffset + 2] >> 32) & 0xFF);
            output[outputOffset + 16 + 5] = (byte)((input[inputOffset + 2] >> 40) & 0xFF);
            output[outputOffset + 16 + 6] = (byte)((input[inputOffset + 2] >> 48) & 0xFF);
            output[outputOffset + 16 + 7] = (byte)((input[inputOffset + 2] >> 56) & 0xFF);

            output[outputOffset + 24 + 0] = (byte)((input[inputOffset + 3] >> 0) & 0xFF);
            output[outputOffset + 24 + 1] = (byte)((input[inputOffset + 3] >> 8) & 0xFF);
            output[outputOffset + 24 + 2] = (byte)((input[inputOffset + 3] >> 16) & 0xFF);
            output[outputOffset + 24 + 3] = (byte)((input[inputOffset + 3] >> 24) & 0xFF);
            output[outputOffset + 24 + 4] = (byte)((input[inputOffset + 3] >> 32) & 0xFF);
            output[outputOffset + 24 + 5] = (byte)((input[inputOffset + 3] >> 40) & 0xFF);
            output[outputOffset + 24 + 6] = (byte)((input[inputOffset + 3] >> 48) & 0xFF);
            output[outputOffset + 24 + 7] = (byte)((input[inputOffset + 3] >> 56) & 0xFF);
        }

        public static void ToBytes1ULongLE(ulong value, byte[] output, long offset)
        {
            output[offset + 0] = (byte)(value >> 0);
            output[offset + 1] = (byte)(value >> 8);
            output[offset + 2] = (byte)(value >> 16);
            output[offset + 3] = (byte)(value >> 24);

            output[offset + 4] = (byte)(value >> 32);
            output[offset + 5] = (byte)(value >> 40);
            output[offset + 6] = (byte)(value >> 48);
            output[offset + 7] = (byte)(value >> 56);
        }

        public static void ToBytes1ULongBE(ulong value, byte[] output, long offset)
        {
            output[offset + 7] = (byte)(value >> 0);
            output[offset + 6] = (byte)(value >> 8);
            output[offset + 5] = (byte)(value >> 16);
            output[offset + 4] = (byte)(value >> 24);

            output[offset + 3] = (byte)(value >> 32);
            output[offset + 2] = (byte)(value >> 40);
            output[offset + 1] = (byte)(value >> 48);
            output[offset + 0] = (byte)(value >> 56);
        }

        public static void ToBytes1UIntLE(uint value, byte[] output, long offset)
        {
            output[offset + 0] = (byte)(value >> 0);
            output[offset + 1] = (byte)(value >> 8);
            output[offset + 2] = (byte)(value >> 16);
            output[offset + 3] = (byte)(value >> 24);
        }

        public static void ToBytes1UShortLE(ushort value, byte[] output, long offset)
        {
            output[offset + 0] = (byte)(value >> 0);
            output[offset + 1] = (byte)(value >> 8);
        }

        // TODO / Shared / Helpers : Memmap / Unwind (like in methods above, so write 128 lines for 128 byte buffer) and check performance if better

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ToULong64BytesLE(byte[] inputBuffer, long inputOffset, ulong[] outputBuffer, long outputOffset)
        {
            ToULong32BytesLE(inputBuffer, inputOffset, outputBuffer, outputOffset);
            ToULong32BytesLE(inputBuffer, inputOffset + 32, outputBuffer, outputOffset + 4);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ToULong128BytesLE(byte[] inputBuffer, long inputOffset, ulong[] outputBuffer, long outputOffset)
        {
            ToULong64BytesLE(inputBuffer, inputOffset, outputBuffer, outputOffset);
            ToULong64BytesLE(inputBuffer, inputOffset + 64, outputBuffer, outputOffset + 8);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ToBytes8ULongLE(ulong[] input, long inputOffset, byte[] output, long outputOffset)
        {
            ToBytes4ULongLE(input, inputOffset, output, outputOffset);
            ToBytes4ULongLE(input, inputOffset + 4, output, outputOffset + 32);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ToBytes16ULongLE(ulong[] input, long inputOffset, byte[] output, long outputOffset)
        {
            ToBytes8ULongLE(input, inputOffset, output, outputOffset);
            ToBytes8ULongLE(input, inputOffset + 8, output, outputOffset + 64);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static unsafe void ToULong64BytesBE(byte* input, long inputOffset, ulong* output, long outputOffset)
        {
            for (int i = 0; i < 8; i++)
            {
                long k = inputOffset + (i * 8);

                output[i + outputOffset] =
                    ((ulong)input[k + 0] << 56) |
                    ((ulong)input[k + 1] << 48) |
                    ((ulong)input[k + 2] << 40) |
                    ((ulong)input[k + 3] << 32) |
                    ((ulong)input[k + 4] << 24) |
                    ((ulong)input[k + 5] << 16) |
                    ((ulong)input[k + 6] << 08) |
                    ((ulong)input[k + 7] << 00);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static unsafe void ToULong64BytesBE(byte[] input, long inputOffset, ulong[] output, long outputOffset)
        {
            for (int i = 0; i < 8; i++)
            {
                long k = inputOffset + (i * 8);

                output[i + outputOffset] =
                    ((ulong)input[k + 0] << 56) |
                    ((ulong)input[k + 1] << 48) |
                    ((ulong)input[k + 2] << 40) |
                    ((ulong)input[k + 3] << 32) |
                    ((ulong)input[k + 4] << 24) |
                    ((ulong)input[k + 5] << 16) |
                    ((ulong)input[k + 6] << 08) |
                    ((ulong)input[k + 7] << 00);
            }
        }

        public static void ToBytes8ULongBE(ulong[] input, long inputOffset, byte[] output, long outputOffset)
        {
            for (int i = 0; i < 8; i++) ToBytes1ULongBE(input[i + inputOffset], output, outputOffset + (i * 8));
        }

        public static void ToBytes6ULongBE(ulong[] input, long inputOffset, byte[] output, long outputOffset)
        {
            for (int i = 0; i < 6; i++) ToBytes1ULongBE(input[i + inputOffset], output, outputOffset + (i * 8));
        }

        public static void ToBytes3ULongBE(ulong[] input, long inputOffset, byte[] output, long outputOffset)
        {
            for (int i = 0; i < 3; i++) ToBytes1ULongBE(input[i + inputOffset], output, outputOffset + (i * 8));
        }

        public static void ToBytes4ULongBE(ulong[] input, long inputOffset, byte[] output, long outputOffset)
        {
            for (int i = 0; i < 4; i++) ToBytes1ULongBE(input[i + inputOffset], output, outputOffset + (i * 8));
        }

        public static void ToULong128BytesBE(byte[] input, long inputOffset, ulong[] output, long outputOffset)
        {
            for (long i = outputOffset; i < 16 + outputOffset; i++)
            {
                long k = inputOffset + (i * 8);

                output[i] =
                    ((ulong)input[k + 0] << 56) |
                    ((ulong)input[k + 1] << 48) |
                    ((ulong)input[k + 2] << 40) |
                    ((ulong)input[k + 3] << 32) |
                    ((ulong)input[k + 4] << 24) |
                    ((ulong)input[k + 5] << 16) |
                    ((ulong)input[k + 6] << 08) |
                    ((ulong)input[k + 7] << 00);
            }
        }


        public static void ToBytes1UIntBE(uint input, byte[] output, long outputOffset)
        {
            output[outputOffset + 0] = (byte)(input >> 24);
            output[outputOffset + 1] = (byte)(input >> 16);
            output[outputOffset + 2] = (byte)(input >> 08);
            output[outputOffset + 3] = (byte)(input >> 00);
        }

        public static byte[] ToNewByteArrayBE(uint value)
        {
            byte[] r = new byte[4];

            r[0] = (byte)((value >> 24) & 0xff);
            r[1] = (byte)((value >> 16) & 0xff);
            r[2] = (byte)((value >> 08) & 0xff);
            r[3] = (byte)((value >> 00) & 0xff);

            return r;
        }

        public static void ToBytes5UIntBE(uint[] input, long inOffset, byte[] output, long outOffset)
        {
            for (long i = 0; i < 5; i++)
            {
                output[outOffset + 0 + (i * 4)] = (byte)(input[i + inOffset] >> 24);
                output[outOffset + 1 + (i * 4)] = (byte)(input[i + inOffset] >> 16);
                output[outOffset + 2 + (i * 4)] = (byte)(input[i + inOffset] >> 08);
                output[outOffset + 3 + (i * 4)] = (byte)(input[i + inOffset] >> 00);
            }
        }

        public static void ToBytes5UIntLE(uint[] input, long inOffset, byte[] output, long outOffset)
        {
            for (long i = 0; i < 5; i++)
            {
                output[outOffset + 0 + (i * 4)] = (byte)(input[i + inOffset] >> 00);
                output[outOffset + 1 + (i * 4)] = (byte)(input[i + inOffset] >> 08);
                output[outOffset + 2 + (i * 4)] = (byte)(input[i + inOffset] >> 16);
                output[outOffset + 3 + (i * 4)] = (byte)(input[i + inOffset] >> 24);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ToUInt16BytesBE(byte[] src, long srcOffset, uint[] dst, long destOffset)
        {
            long so = srcOffset;

            for (int i = 0; i < 4; i++)
            {
                dst[i + destOffset] =
                            (uint)(src[so + 0] << 24) |
                            (uint)(src[so + 1] << 16) |
                            (uint)(src[so + 2] << 08) |
                            (uint)(src[so + 3] << 00);

                so += 4;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ToUInt24BytesBE(byte[] src, long srcOffset, uint[] dst, long destOffset)
        {
            long so = srcOffset;

            for (int i = 0; i < 6; i++)
            {
                dst[i + destOffset] =
                            (uint)(src[so + 0] << 24) |
                            (uint)(src[so + 1] << 16) |
                            (uint)(src[so + 2] << 08) |
                            (uint)(src[so + 3] << 00);

                so += 4;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ToUInt32BytesBE(byte[] src, long srcOffset, uint[] dst, long destOffset)
        {
            long so = srcOffset;

            for (int i = 0; i < 8; i++)
            {
                dst[i + destOffset] =
                            (uint)(src[so + 0] << 24) |
                            (uint)(src[so + 1] << 16) |
                            (uint)(src[so + 2] << 08) |
                            (uint)(src[so + 3] << 00);

                so += 4;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        public static void ToULong24BytesLE(byte* src, ulong* output)
        {
            output[0] =
                ((ulong)src[0] << 00) |
                ((ulong)src[1] << 08) |
                ((ulong)src[2] << 16) |
                ((ulong)src[3] << 24) |
                ((ulong)src[4] << 32) |
                ((ulong)src[5] << 40) |
                ((ulong)src[6] << 48) |
                ((ulong)src[7] << 56);

            src += 8;

            output[1] =
                ((ulong)src[0] << 00) |
                ((ulong)src[1] << 08) |
                ((ulong)src[2] << 16) |
                ((ulong)src[3] << 24) |
                ((ulong)src[4] << 32) |
                ((ulong)src[5] << 40) |
                ((ulong)src[6] << 48) |
                ((ulong)src[7] << 56);

            src += 8;

            output[2] =
                ((ulong)src[0] << 00) |
                ((ulong)src[1] << 08) |
                ((ulong)src[2] << 16) |
                ((ulong)src[3] << 24) |
                ((ulong)src[4] << 32) |
                ((ulong)src[5] << 40) |
                ((ulong)src[6] << 48) |
                ((ulong)src[7] << 56);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        public static void ToULong24BytesLE(byte[] src, long srcOffset, ulong[] output, long outputOffset)
        {
            long i = srcOffset, o = outputOffset;

            output[o + 0] =
                ((ulong)src[i + 0] << 00) |
                ((ulong)src[i + 1] << 08) |
                ((ulong)src[i + 2] << 16) |
                ((ulong)src[i + 3] << 24) |
                ((ulong)src[i + 4] << 32) |
                ((ulong)src[i + 5] << 40) |
                ((ulong)src[i + 6] << 48) |
                ((ulong)src[i + 7] << 56);

            i += 8;

            output[o + 1] =
                ((ulong)src[i + 0] << 00) |
                ((ulong)src[i + 1] << 08) |
                ((ulong)src[i + 2] << 16) |
                ((ulong)src[i + 3] << 24) |
                ((ulong)src[i + 4] << 32) |
                ((ulong)src[i + 5] << 40) |
                ((ulong)src[i + 6] << 48) |
                ((ulong)src[i + 7] << 56);

            i += 8;

            output[o + 2] =
                ((ulong)src[i + 0] << 00) |
                ((ulong)src[i + 1] << 08) |
                ((ulong)src[i + 2] << 16) |
                ((ulong)src[i + 3] << 24) |
                ((ulong)src[i + 4] << 32) |
                ((ulong)src[i + 5] << 40) |
                ((ulong)src[i + 6] << 48) |
                ((ulong)src[i + 7] << 56);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ToULong24BytesBE(byte[] src, long srcOffset, ulong[] output, long outputOffset)
        {
            long i = srcOffset, o = outputOffset;

            output[o + 0] =
                ((ulong)src[i + 7] << 00) |
                ((ulong)src[i + 6] << 08) |
                ((ulong)src[i + 5] << 16) |
                ((ulong)src[i + 4] << 24) |
                ((ulong)src[i + 3] << 32) |
                ((ulong)src[i + 2] << 40) |
                ((ulong)src[i + 1] << 48) |
                ((ulong)src[i + 0] << 56);

            i += 8;

            output[o + 1] =
                ((ulong)src[i + 7] << 00) |
                ((ulong)src[i + 6] << 08) |
                ((ulong)src[i + 5] << 16) |
                ((ulong)src[i + 4] << 24) |
                ((ulong)src[i + 3] << 32) |
                ((ulong)src[i + 2] << 40) |
                ((ulong)src[i + 1] << 48) |
                ((ulong)src[i + 0] << 56);

            i += 8;

            output[o + 2] =
                ((ulong)src[i + 7] << 00) |
                ((ulong)src[i + 6] << 08) |
                ((ulong)src[i + 5] << 16) |
                ((ulong)src[i + 4] << 24) |
                ((ulong)src[i + 3] << 32) |
                ((ulong)src[i + 2] << 40) |
                ((ulong)src[i + 1] << 48) |
                ((ulong)src[i + 0] << 56);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ToBytes2ULongLE(ulong[] input, long inputOffset, byte[] output, long outputOffset)
        {
            long i = inputOffset, o = outputOffset;

            output[o + 0] = (byte)(input[i] >> 00);
            output[o + 1] = (byte)(input[i] >> 08);
            output[o + 2] = (byte)(input[i] >> 16);
            output[o + 3] = (byte)(input[i] >> 24);
            output[o + 4] = (byte)(input[i] >> 32);
            output[o + 5] = (byte)(input[i] >> 40);
            output[o + 6] = (byte)(input[i] >> 48);
            output[o + 7] = (byte)(input[i] >> 56);

            o += 8;
            i += 1;

            output[o + 0] = (byte)(input[i] >> 00);
            output[o + 1] = (byte)(input[i] >> 08);
            output[o + 2] = (byte)(input[i] >> 16);
            output[o + 3] = (byte)(input[i] >> 24);
            output[o + 4] = (byte)(input[i] >> 32);
            output[o + 5] = (byte)(input[i] >> 40);
            output[o + 6] = (byte)(input[i] >> 48);
            output[o + 7] = (byte)(input[i] >> 56);
        }

        #endregion
    }
}
