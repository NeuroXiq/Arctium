namespace Arctium.Shared.Helpers.Buffers
{
    public static partial class ByteBuffer
    {
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
    }
}
