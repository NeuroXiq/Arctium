namespace Arctium.Cryptography.HashFunctions.Hashes.Configuration
{
    public static class HashFunctionsConfig
    {
        /// <summary>
        /// Size of the internal buffer as a multiply of input block size of the specific hash function.
        /// Example: if Hash function takes 64-bytes input block, HashDataBuffer_BufferSize == 16 means
        /// that there will be allocated 64 * 16 bytes and hash procedure runs after reaching this limit.
        /// </summary>
        public static int Common_HashDataBuffer_BufferSize = 0x20;
    }
}