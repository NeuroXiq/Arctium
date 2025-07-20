using Arctium.Cryptography.HashFunctions.Hashes.Algorithms;
using Arctium.Shared;
using System;
using System.IO;

namespace Arctium.Cryptography.HashFunctions.Hashes
{
    public abstract class Streebog : HashFunction
    {
        public BlockBufferWithCallback blockBuffer;

        private StreebogAlgorithm.State state;

        public Streebog(int hashSize) : base(512, hashSize)
        {
            blockBuffer = new BlockBufferWithCallback(GlobalConfig.DefaultHashBufferBlockCount * InputBlockSizeBytes, InputBlockSizeBytes, HashBytes);
            StreebogAlgorithm.HashSize algoHashSize = hashSize == 256 ? StreebogAlgorithm.HashSize.Size256 : StreebogAlgorithm.HashSize.Size512;

            state = StreebogAlgorithm.Init(algoHashSize);
        }

        public override void HashBytes(byte[] buffer) => blockBuffer.Load(buffer, 0, buffer.Length);

        public override long HashBytes(Stream stream) => blockBuffer.Load(stream);

        public override void HashBytes(byte[] buffer, long offset, long length)
        {
            StreebogAlgorithm.Process512BitBlocks(state, buffer, offset, length);
        }

        public override byte[] HashFinal()
        {
            byte[] lastBlock = new byte[64];
            byte[] hash = new byte[HashSizeBytes];
            long lastBytesLength;

            blockBuffer.Flush(lastBlock, 0, out lastBytesLength);

            StreebogAlgorithm.ProcessLastBlock(state, lastBlock, 0, lastBytesLength);

            StreebogAlgorithm.GetHash(state, hash, 0);

            return hash;
        }

        public override void Reset() => StreebogAlgorithm.Reset(state);
    }

    /// <summary>
    /// GOST R 34.11-2012 / Streebog hash function.
    /// RFC 6986
    /// 256 bits output size
    /// </summary>
    public class Streebog_256 : Streebog
    {
        public Streebog_256() : base(256) { }
    }

    /// <summary>
    /// GOST R 34.11-2012 / Streebog hash function.
    /// RFC 6986
    /// 512 bits output size
    /// </summary>
    public class Streebog_512 : Streebog
    {
        public Streebog_512() : base(512) { }
    }
}
