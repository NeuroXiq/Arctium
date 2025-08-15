using Arctium.Shared;

namespace Arctium.Cryptography.HashFunctions.Hashes.HashHelpers
{
    /// <summary>
    /// Helper class to store block of bytes
    /// </summary>
    unsafe class BlockCache
    {
        public byte[] Buffer;

        public bool HaveData;

        private long blockLength;

        public BlockCache(long blockLength)
        {
            Buffer = new byte[blockLength];
            this.blockLength = blockLength;
            HaveData = false;
        }

        public void SetData(byte* buffer, long offset)
        {
            MemCpy.Copy(buffer + offset, Buffer, this.blockLength);
            HaveData = true;
        }

        public void ClearData()
        {
            HaveData = false;
        }
    }
}
