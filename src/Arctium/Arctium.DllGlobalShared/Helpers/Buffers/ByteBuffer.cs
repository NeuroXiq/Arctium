namespace Arctium.DllGlobalShared.Helpers.Buffers
{
    public static class ByteBuffer
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
        public static long Copy(byte[] inputBuffer, long offset, byte[] outputBuffer, long outputOffset,  long length)
        {
            for (long i = offset; i < length; i++, outputOffset++)
            {
                outputBuffer[outputOffset] = inputBuffer[i];
            }

            return length;
        }
    }
}
