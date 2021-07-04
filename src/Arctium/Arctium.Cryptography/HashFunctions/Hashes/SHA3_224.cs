using Arctium.Cryptography.HashFunctions.Hashes.Configuration;
using Arctium.Shared.Helpers.Buffers;
using System.IO;

namespace Arctium.Cryptography.HashFunctions.Hashes
{
    public unsafe class SHA3_224 : HashFunction
    {
        const int R_SpongeParam = 1600 - 448;

        readonly SHA3_Shared sha3Shared;
        ByteBufferWithUnsafeCallback blockBuffer;

        public SHA3_224() : base(R_SpongeParam, 224)
        {
            sha3Shared = new SHA3_Shared(R_SpongeParam);
            int bufferSize = HashFunctionsConfig.BufferSizeInBlocks * InputBlockSizeBytes;
            blockBuffer = new ByteBufferWithUnsafeCallback(bufferSize, ExecuteHashing);
        }

        private void ExecuteHashing(byte* buffer, long length)
        {
            sha3Shared.MainHashComputation(buffer, length);
        }

        public override void HashBytes(byte[] buffer)
        {
            LoadedBytes += blockBuffer.Load(buffer);
        }

        public override long HashBytes(Stream stream)
        {
            long loaded = blockBuffer.Load(stream);
            LoadedBytes += loaded;

            return loaded;
        }

        public override void HashBytes(byte[] buffer, long offset, long length)
        {
            LoadedBytes += blockBuffer.Load(buffer, offset, length);
        }

        public override byte[] HashFinal()
        {
            blockBuffer.Load(sha3Shared.SHA3_GetLastBlockWithPad_HashFunction(LoadedBytes));
            byte[] hash = new byte[28];

            if (blockBuffer.HasData) blockBuffer.FlushBuffer();

            sha3Shared.GetCurrentState(hash, 0, 28);

            return hash;
        }

        public override void Reset()
        {
            sha3Shared.ResetState();
            blockBuffer.Clear();
            LoadedBytes = 0;
        }
    }
}
