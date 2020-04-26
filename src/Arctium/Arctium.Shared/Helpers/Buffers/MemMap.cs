using System.Runtime.CompilerServices;

namespace Arctium.Shared.Helpers.Buffers
{
    /// <summary>
    /// Performs some common mapping from blocks of types to other types.
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
        //
        // Unsafe end
        //

    }
}
