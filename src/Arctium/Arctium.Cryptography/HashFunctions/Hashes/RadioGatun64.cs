using Arctium.Cryptography.HashFunctions.Hashes.Algorithms;
using Arctium.Shared;
using System;
using System.IO;

namespace Arctium.Cryptography.HashFunctions.Hashes
{
    public class RadioGatun64 : HashFunction
    {
        BlockBufferWithCallback blockBuffer;
        RadioGatun64Algorithm.State state;

        public RadioGatun64() : base(192, 256)
        {
            blockBuffer = new BlockBufferWithCallback(GlobalConfig.DefaultHashBufferBlockCount * InputBlockSizeBytes, InputBlockSizeBytes, HashBytes);
            state = RadioGatun64Algorithm.Init();
        }

        public override void HashBytes(byte[] buffer) => blockBuffer.Load(buffer, 0, buffer.Length);

        public override long HashBytes(Stream stream) => blockBuffer.Load(stream);

        public override void HashBytes(byte[] buffer, long offset, long length)
        {
            RadioGatun64Algorithm.Process192BitBlocks(state, buffer, offset, length);
        }

        /// <summary>
        /// First call to this method generates call. Second and more calls works as Extendable Output Function
        /// that uses current hash state to generate next output. This means that multiple calls to this method
        /// gives different hashed. Only first hash is corrent RadioGatun hash
        /// </summary>
        /// <returns></returns>
        public override byte[] HashFinal()
        {
            byte[] hash = new byte[32];
            byte[] bytesNotAligned = new byte[24];
            long lastBlockLength;

            blockBuffer.Flush(bytesNotAligned, 0, out lastBlockLength);

            RadioGatun64Algorithm.ProcessLastBlock(state, bytesNotAligned, 0, lastBlockLength);
            RadioGatun64Algorithm.GetHash(state, hash, 0);


            return hash;
        }

        public override void Reset()
        {
            RadioGatun64Algorithm.Reset(state);
        }
    }
}
