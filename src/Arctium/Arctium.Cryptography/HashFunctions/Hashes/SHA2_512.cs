
using System.IO;
using Arctium.Cryptography.HashFunctions.Hashes.Configuration;
using Arctium.Shared.Helpers.Binary;
using Arctium.Shared.Helpers.Buffers;

namespace  Arctium.Cryptography.HashFunctions.Hashes
{
    public unsafe class SHA2_512 : HashFunction
    {
        static readonly ulong[] InitialHashValue = new ulong[]
        {
            0x6a09e667f3bcc908,
            0xbb67ae8584caa73b,
            0x3c6ef372fe94f82b,
            0xa54ff53a5f1d36f1,
            0x510e527fade682d1,
            0x9b05688c2b3e6c1f,
            0x1f83d9abfb41bd6b,
            0x5be0cd19137e2179
        };

        ulong[] messageScheduleBuffer;
        ulong[] hashValue;
        ByteBufferWithUnsafeCallback blockBuffer;

        public SHA2_512() : base(1024, 512)
        {
            messageScheduleBuffer = new ulong[80];
            hashValue = GetInitialHashValue();
            int bufferSize = HashFunctionsConfig.BufferSizeInBlocks * InputBlockSizeBytes;
            blockBuffer = new ByteBufferWithUnsafeCallback(bufferSize, ExecuteHashing);
        }

        private ulong[] GetInitialHashValue()
        {
            ulong[] init = new ulong[8];
            InitialHashValue.CopyTo(init, 0);

            return init;
        }

        protected void ExecuteHashing(byte* buffer, long length)
        {
            SHA2_384_512_Shared.PerformHashComputation(hashValue, buffer, length, messageScheduleBuffer);
        }

        public override void Reset()
        {
            hashValue = GetInitialHashValue();
            LoadedBytes = 0;
            blockBuffer.Clear();
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
            bool isPaddingNeeded = LoadedBytes % ((long)InputBlockSizeBytes) != 0 || LoadedBytes == 0;

            if (isPaddingNeeded)
            {
                blockBuffer.Load(SHA2_384_512_Shared.GetPadding(LoadedBytes));
            }

            if (blockBuffer.HasData) blockBuffer.FlushBuffer();

            byte[] hash = new byte[64];
            for (int i = 0; i < 8; i++)
            {
                BinConverter.ToBytesBE(hash, i * 8, hashValue[i]);
            }

            return hash;
        }
    }
}
