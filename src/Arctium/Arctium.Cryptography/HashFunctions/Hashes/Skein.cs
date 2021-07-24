using Arctium.Cryptography.HashFunctions.Hashes.Algorithms;
using System.IO;
using System;
using System.Collections.Generic;
using System.Text;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Cryptography.HashFunctions.Hashes.Configuration;

namespace Arctium.Cryptography.HashFunctions.Hashes
{
    public abstract class Skein : HashFunction
    {
        protected SkeinAlgorithm.Context context;
        protected BlockBufferWithLastBlock memBuffer;
        private byte[] lastBlock;

        public Skein(int inputBlockSize, int hashSize) : base(inputBlockSize, hashSize)
        {
            context = SkeinAlgorithm.SimpleInitialise(inputBlockSize, hashSize);
            memBuffer = new BlockBufferWithLastBlock(inputBlockSize / 8, HashFunctionsConfig.BufferSizeInBlocks, HashNotLastBlockBufferCallback);
            lastBlock = new byte[inputBlockSize / 8];
        }

        public override void HashBytes(byte[] buffer)
        {
            memBuffer.Load(buffer);
        }

        public override long HashBytes(Stream stream)
        {
            return memBuffer.Load(stream);
        }

        public override void HashBytes(byte[] buffer, long offset, long length)
        {
            memBuffer.Load(buffer, offset, length);
        }

        public override void Reset()
        {
        
        }

        public override byte[] HashFinal()
        {
            long lastBlockLength = memBuffer.FlushWithLastBlock(lastBlock, 0);
            HashLastBlock(lastBlock, 0, lastBlockLength);

            byte[] hash = new byte[HashSizeBytes];
            SkeinAlgorithm.Output(context, hash, 0);

            return hash;
        }

        protected abstract void HashNotLastBlockBufferCallback(byte[] buffer, long offset, long length);
        protected abstract void HashLastBlock(byte[] buffer, long offset, long length);
    }
}
