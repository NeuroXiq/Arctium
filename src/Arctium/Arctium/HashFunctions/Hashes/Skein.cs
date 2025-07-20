using Arctium.Cryptography.HashFunctions.Hashes.Algorithms;
using System.IO;
using Arctium.Shared.Helpers.Buffers;


namespace Arctium.Cryptography.HashFunctions.Hashes
{
    public abstract class Skein : HashFunction
    {
        public enum InternalStateSize
        {
            Bits_256 = 256,
            Bits_512 = 512,
            Bits_1024 = 1024
        }

        public InternalStateSize StateSize { get; private set; }

        protected SkeinAlgorithm.Context context;
        protected BlockBufferWithLastBlock memBuffer;
        private byte[] lastBlock;

        public Skein(InternalStateSize stateSize, int hashSize) : base((int)stateSize, hashSize)
        {
            StateSize = stateSize;
            int inputBlockSize = (int)stateSize;
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
            context = SkeinAlgorithm.SimpleInitialise((int)StateSize, HashSizeBits);
            memBuffer.Reset();
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
