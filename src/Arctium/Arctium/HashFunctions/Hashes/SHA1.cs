using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Arctium.Shared;
using Arctium.Cryptography.HashFunctions.Hashes.Algorithms;
using Arctium.Shared;

namespace Arctium.Cryptography.HashFunctions.Hashes
{
    public unsafe class SHA1 : HashFunction
    {
        BlockBufferWithCallback membuf;
        SHA1Algorithm.Context context;

        public SHA1(): base(512, 160)
        {
            membuf = new BlockBufferWithCallback(HashFunctionsConfig.BufferSizeInBlocks * 16, base.InputBlockSizeBytes, BufferCallback);
            context = SHA1Algorithm.InitializeContext();
        }


        public override void HashBytes(byte[] buffer) { membuf.Load(buffer, 0, buffer.Length); }

        public override void HashBytes(byte[] buffer, long offset, long length) { membuf.Load(buffer, offset, length); }

        public override long HashBytes(Stream stream) { return membuf.Load(stream); }

        public override byte[] HashFinal()
        {
            byte[] hash = new byte[20];
            byte[] lastNotFullBlockBytes = new byte[64];
            long lastBytesCount;

            membuf.Flush(lastNotFullBlockBytes, 0, out lastBytesCount);

            SHA1Algorithm.HashLastBlock(context, lastNotFullBlockBytes, 0, lastBytesCount);
            SHA1Algorithm.GetHash(context, hash, 0);

            return hash;
        }

        public override void Reset()
        {
            SHA1Algorithm.ResetContext(context);
            membuf.Reset();
        }

        //
        // Private
        //
        
        private void BufferCallback(byte[] buffer, long offset, long count)
        {
           fixed (byte* b = &buffer[offset])
           {
                SHA1Algorithm.HashFullBlocks(context, b, 0, count);
           } 
        }
    }
}
