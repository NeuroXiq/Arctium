using System.IO;
using Arctium.Shared;
using Arctium.Cryptography.HashFunctions.Hashes.Algorithms;

namespace Arctium.Cryptography.HashFunctions.Hashes
{
    public class RIPEMD_160 : HashFunction
    {
        BlockBufferWithCallback blockBuffer;
        RIPEMDAlgorithm.State state;

        public RIPEMD_160() : base(512, 160) 
        {
            blockBuffer = new BlockBufferWithCallback(GlobalConfig.DefaultHashBufferBlockCount * 512, 64, HashBytes);
            state = RIPEMDAlgorithm.Init();
        }

        public override void HashBytes(byte[] buffer) => blockBuffer.Load(buffer, 0, buffer.Length);

        public override long HashBytes(Stream stream) => blockBuffer.Load(stream);

        public override void HashBytes(byte[] buffer, long offset, long length)
        {
            RIPEMDAlgorithm.Process512BitBlocks(state, buffer, offset, length);
        }

        public override byte[] HashFinal()
        {
            byte[] lastBlock = new byte[128];
            byte[] hash = new byte[20];
            long lastLength;
            
            blockBuffer.Flush(lastBlock, 0, out lastLength);
            RIPEMDAlgorithm.ProcessLastBlock(state, lastBlock, 0, lastLength);
            RIPEMDAlgorithm.GetHash(state, hash, 0);

            return hash;
        }

        public override void Reset()
        {
            blockBuffer.Reset();
            RIPEMDAlgorithm.Reset(state);
        }
    }
}
