using System.IO;
using Arctium.Cryptography.HashFunctions.Hashes.Algorithms;

namespace Arctium.Cryptography.HashFunctions.Hashes
{
    public abstract class JH : HashFunction
    {
        protected JHAlgorithm.JHContext context;
        protected BlockBufferWithCallback bufferWithCallback;

        protected JH(int hashSize) : base(512, hashSize) 
        {
            context = JHAlgorithm.Initialize(hashSize);
            bufferWithCallback = new BlockBufferWithCallback(HashFunctionsConfig.BufferSizeInBlocks * InputBlockSizeBytes, InputBlockSizeBytes, BufferCallback);
        }

        public override void Reset()
        {
            JHAlgorithm.Reset(context);
            bufferWithCallback.Reset();
        }

        
        public override void HashBytes(byte[] buffer)
        {
            bufferWithCallback.Load(buffer, 0, buffer.Length); 
        }

        public override void HashBytes(byte[] buffer, long offset, long length)
        {
            bufferWithCallback.Load(buffer, offset, length); 
        }

        public override long HashBytes(Stream stream)
        {
            return bufferWithCallback.Load(stream); 
        }

        public override byte[] HashFinal()
        {
            byte[] outputHash = new byte[HashSizeBytes];
            byte[] lastBytes = new byte[64];
            long lastBytesLength;

            bufferWithCallback.Flush(lastBytes, 0, out lastBytesLength);

            JHAlgorithm.HashLastBlock(context, lastBytes, 0, lastBytesLength);
            JHAlgorithm.GetHash(context, outputHash, 0);

            return outputHash;
        }

        private void BufferCallback(byte[] buffer, long offset, long length)
        {
            JHAlgorithm.HashBytes(context, buffer, offset, length);
        }
    }
}
