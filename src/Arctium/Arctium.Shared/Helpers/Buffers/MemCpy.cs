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

        public static long Copy(byte* inputBuffer, long offset, byte[] outputBuffer, long outputOffset, long length)
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

        public static void Copy(uint* src, long srcOffset, uint[] dst, long destOffset, long length)
        {
            for (int i = 0; i < length; i++)
            {
                dst[destOffset + i] = src[i];
            }
        }

        public static void Copy(ulong* src, ulong[] dst)
        {
            for (int i = 0; i < dst.Length; i++)
            {
                dst[i] = src[i];
            }
        }

        //
        // Fixed Length Copy
        //

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Copy8Uint(uint* src, uint* dst)
        {
            src[0] = dst[0];
            src[1] = dst[1];
            src[2] = dst[2];
            src[3] = dst[3];
            src[4] = dst[4];
            src[5] = dst[5];
            src[6] = dst[6];
            src[7] = dst[7];
        }

        public static void Copy(ulong[] source, ulong* dst)
        {
            for (int i = 0; i < source.Length; i++)
            {
                dst[i] = source[i];
            }
        }

        /// <summary>
        /// Unwided version od copy 2 uint values to second 2 uint values
        /// </summary>
        /// <param name="source"></param>
        /// <param name="dst"></param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Copy8ULong(ulong* source, ulong* dst)
        {
            dst[0] = source[0];
            dst[1] = source[1];
            dst[2] = source[2];
            dst[3] = source[3];
            dst[4] = source[4];
            dst[5] = source[5];
            dst[6] = source[6];
            dst[7] = source[7];
        }

        public static void Copy(byte* src, byte[] dst, long count)
        {
            for (int i = 0; i < count; i++)
            {
                dst[i] = src[i];
            }
        }

        //
        // End fixed length copy
        //

        /// <summary>
        /// Creates managed version of the  unsafe array.
        /// </summary>
        /// <param name="input"></param>
        /// <param name="length"></param>
        public static uint[] ToArray(uint* input, int length)
        {
            uint[] result = new uint[length];

            for (int i = 0; i < length; i++) result[i] = input[i];

            return result;
        }

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

        public static void Copy(uint[] src, uint* dst)
        {
            for (int i = 0; i < src.Length; i++)
            {
                dst[i] = src[i];
            }
        }

        public static void Copy(ulong[] src, ulong[] dst)
        {
            Copy(src, 0, src.Length, dst, 0);
        }

        public static void Copy(ulong[] src, long srcOffset, long length, ulong[] dst, long dstOffset)
        {
            for(long i = 0; i < length; i++) dst[dstOffset + i] = src[srcOffset + i];
        }

        public static byte[] CopyToNewArray(byte[] src, int srcOffs, long length)
        {
            byte[] newArr = new byte[length];
            MemCpy.Copy(src, srcOffs, newArr, 0, length);

            return newArr;
        }
    }
}
