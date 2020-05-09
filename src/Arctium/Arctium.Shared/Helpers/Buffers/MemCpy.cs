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

        public static long Copy(byte[] source, byte[] destination)
        {
            if (source.Length != destination.Length)
                throw new ArgumentException("Length of the source array do not match length of the destination");
            return Copy(source, 0, destination, 0, destination.Length);
        }

        public static byte[] CopyRange(byte[] buffer, long offset, long length)
        {
            byte[] range = new byte[length];

            Copy(buffer, offset, range, 0, length);

            return range;
        }


        #region unmanaged

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

        public static void Copy(byte* src, long srcOffset, byte* output, long outOffset, long length)
        {
            for (int i = 0; i < length; i++)
            {
                output[i + outOffset] = src[srcOffset + i];
            }
        }

        public static void Copy(uint* src, uint* dst, long length)
        {
            for (long i = 0; i < length; i++)
            {
                dst[i] = src[i];
            }
        }

        #endregion

        //
        // basic copy method (roots)



        // basic copy method end
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


        public static void Copy(byte[] key2, uint* input, uint[] output, long outputOffset, long length)
        {
            for (int i = 0; i < length; i++)
            {
                output[i + outputOffset] = input[i];
            }
        }


        public static void Copy(byte* src, byte* dst, long length)
        {
            Copy(src, 0, dst, 0, length);
        }
    }
}
