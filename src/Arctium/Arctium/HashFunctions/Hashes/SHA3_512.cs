using Arctium.Cryptography.HashFunctions.Hashes.Algorithms;

using Arctium.Shared.Helpers.Buffers;
using System;
using System.IO;

namespace Arctium.Cryptography.HashFunctions.Hashes
{
    public unsafe class SHA3_512 : HashFunction
    {
        const int HashSizeInBits = 512;
        const int R_SpongeParam = 1600 - (2 * HashSizeInBits);

        SHA3_Shared sha3Shared;
        ByteBufferWithUnsafeCallback byteBuffer;

        public SHA3_512() : base(R_SpongeParam, HashSizeInBits)
        {
            sha3Shared = new SHA3_Shared(R_SpongeParam);
            byteBuffer = new ByteBufferWithUnsafeCallback(HashFunctionsConfig.BufferSizeInBlocks * InputBlockSizeBytes, sha3Shared.MainHashComputation);
        }

        public override void HashBytes(byte[] buffer)
        {
            LoadedBytes += byteBuffer.Load(buffer);
        }

        public override long HashBytes(Stream stream)
        {
            long loaded = byteBuffer.Load(stream);

            LoadedBytes += loaded;

            return loaded;
        }

        public override void HashBytes(byte[] buffer, long offset, long length)
        {
            LoadedBytes = byteBuffer.Load(buffer, offset, length);
        }

        public override byte[] HashFinal()
        {
            byteBuffer.Load(sha3Shared.SHA3_GetLastBlockWithPad_HashFunction(LoadedBytes));

            if (byteBuffer.HasData) byteBuffer.FlushBuffer();

            byte[] hash = new byte[64];

            sha3Shared.GetCurrentState(hash, 0, 64);

            return hash;
        }

        public override void Reset()
        {
            sha3Shared.ResetState();
            byteBuffer.Clear();
            LoadedBytes = 0;
        }
    }
}
