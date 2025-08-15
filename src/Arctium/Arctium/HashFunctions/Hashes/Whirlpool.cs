using System;
using System.IO;
using Arctium.Cryptography.HashFunctions.Hashes.Algorithms;
using Arctium.Shared;

namespace Arctium.Cryptography.HashFunctions.Hashes
{
    public class Whirlpool : HashFunction
    {
        BlockBufferWithCallback blockBuffer;
        WhirlpoolAlgorithm.State state;

        public Whirlpool() : base(512, 512)
        {
            blockBuffer = new BlockBufferWithCallback(16 * 2048, 64, HashBytes);
            state = WhirlpoolAlgorithm.InitState();
        }

        public override void HashBytes(byte[] buffer) => blockBuffer.Load(buffer, 0, buffer.Length);

        public override long HashBytes(Stream stream) => blockBuffer.Load(stream);

        public override void HashBytes(byte[] buffer, long offset, long length)
        {
            WhirlpoolAlgorithm.Process512BitBlocks(state, buffer, offset, length);
        }

        public override byte[] HashFinal()
        {
            byte[] lastBlock = new byte[64];
            byte[] hash = new byte[64];
            long lastBlockLength;
            blockBuffer.Flush(lastBlock, 0, out lastBlockLength);

            WhirlpoolAlgorithm.ProcessLastBlock(state, lastBlock, 0, lastBlockLength);
            WhirlpoolAlgorithm.GetHash(state, hash, 0);

            return hash;
        }

        public override void Reset()
        {
            WhirlpoolAlgorithm.ResetState(state);
            blockBuffer.Reset();
        }
    }
}
