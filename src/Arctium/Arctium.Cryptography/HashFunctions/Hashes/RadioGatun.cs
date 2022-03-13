using Arctium.Cryptography.HashFunctions.Hashes.Algorithms;
using Arctium.Shared;
using System;
using System.IO;

namespace Arctium.Cryptography.HashFunctions.Hashes
{
    public class RadioGatun : HashFunction
    {
        BlockBufferWithCallback blockBuffer;
        RadioGatunAlgorithm.State state;

        public RadioGatun() : base(192, 256)
        {
            blockBuffer = new BlockBufferWithCallback(GlobalConfig.DefaultHashBufferBlockCount * InputBlockSizeBytes, InputBlockSizeBytes, HashBytes);
            state = RadioGatunAlgorithm.Init();
        }

        public override void HashBytes(byte[] buffer) => blockBuffer.Load(buffer, 0, buffer.Length);

        public override long HashBytes(Stream stream) => blockBuffer.Load(stream);

        public override void HashBytes(byte[] buffer, long offset, long length)
        {
            RadioGatunAlgorithm.Process192BitBlocks(state, buffer, offset, length);
        }

        public override byte[] HashFinal()
        {
            byte[] hash = new byte[32];
            byte[] bytesNotAligned = new byte[24];
            long lastBlockLength;

            blockBuffer.Flush(bytesNotAligned, 0, out lastBlockLength);

            RadioGatunAlgorithm.ProcessLastBlock(state, bytesNotAligned, 0, lastBlockLength);
            RadioGatunAlgorithm.GetHash(state, hash, 0);


            return hash;
        }

        public override void Reset()
        {
            RadioGatunAlgorithm.Reset(state);
        }
    }
}
