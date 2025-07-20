using Arctium.Cryptography.HashFunctions.Hashes.Algorithms;
using Arctium.Shared;
using System;
using System.IO;

namespace Arctium.Cryptography.HashFunctions.Hashes
{
    public class RadioGatun32 : HashFunction
    {
        BlockBufferWithCallback blockBuffer;
        RadioGatun32Algorithm.State state;

        public RadioGatun32() : base(96, 256)
        {
            blockBuffer = new BlockBufferWithCallback(GlobalConfig.DefaultHashBufferBlockCount * InputBlockSizeBytes, InputBlockSizeBytes, HashBytes);
            state = RadioGatun32Algorithm.Init();
        }

        public override void HashBytes(byte[] buffer) => blockBuffer.Load(buffer, 0, buffer.Length);

        public override long HashBytes(Stream stream) => blockBuffer.Load(stream);

        public override void HashBytes(byte[] buffer, long offset, long length)
        {
            RadioGatun32Algorithm.Process96BitBlocks(state, buffer, offset, length);
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
            byte[] bytesNotAligned = new byte[12];
            long lastBlockLength;

            blockBuffer.Flush(bytesNotAligned, 0, out lastBlockLength);

            RadioGatun32Algorithm.ProcessLastBlock(state, bytesNotAligned, 0, lastBlockLength);
            RadioGatun32Algorithm.GetHash(state, hash, 0);


            return hash;
        }

        public override void Reset()
        {
            RadioGatun32Algorithm.Reset(state);
        }
    }
}
