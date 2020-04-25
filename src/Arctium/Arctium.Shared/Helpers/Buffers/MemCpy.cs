using System;
using System.Runtime.CompilerServices;

namespace Arctium.Shared.Helpers.Buffers
{
    public static unsafe partial class MemCpy
    {

        //
        // Managed copy
        //



        /// <summary>
        /// Copy bytes from one buffer to another.
        /// </summary>
        /// <param name="inputBuffer"></param>
        /// <param name="offset"></param>
        /// <param name="length"></param>
        /// <param name="outputBuffer"></param>
        /// <param name="outputOffset"></param>
        /// <returns>Number of bytes copied to output buffer</returns>
        /// 
        //TODO remove
        public static long Copy(byte[] inputBuffer, long offset, byte[] outputBuffer, long outputOffset, long length)
        {
            long copyEnd = offset + length;
            for (long i = offset, j = outputOffset; i < copyEnd; i++, outputOffset++)
            {
                outputBuffer[outputOffset] = inputBuffer[i];
            }

            return length;
        }

        public static byte[] Range(byte[] buffer, long offset, long length)
        {
            byte[] range = new byte[length];

            Copy(buffer, offset, range, 0, length);

            return range;
        }

        public static void Copy(byte[] key2, uint* input, uint[] output, long outputOffset, long length)
        {
            for (int i = 0; i < length; i++)
            {
                output[i + outputOffset] = input[i];
            }
        }

        //
        // Unmanaged copy version
        //

        //
        // Fixed Length Copy
        //

        /// <summary>
        /// Unwided version od copy 2 uint values to second 2 uint values
        /// </summary>
        /// <param name="source"></param>
        /// <param name="dst"></param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Copy2UIntToUInt(uint* source, uint* dst)
        {
            dst[0] = source[0];
            dst[1] = source[1];
        }

        //
        // End fixed length copy
        //





        public static void Copy(byte[] input, long inputOffset, byte* output, int outputOffset, long length)
        {
            for (long i = 0; i < length; i++)
            {
                output[i + outputOffset] = input[i + inputOffset];
            }
        }

        public static void Copy(byte[] input, byte* output)
        {
            Copy(input, 0, output, 0, input.Length);
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
    }
}
