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
        //
        // Unsafe
        //

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
        public static byte[] ToBytesBE(uint* uintPtr, int length)
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


        /// <summary>
        /// Converts 32 bytes to 8 uint values where input bytes 
        /// are intepreted as little-endia 4-bytes integers
        /// </summary>
        /// <param name="prekey"></param>
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


        //
        // Unsafe end
        //

    }
}
