using Arctium.Cryptography.HashFunctions.Hashes.Algorithms;

using Arctium.Shared.Helpers.Binary;
using Arctium.Shared.Helpers.Buffers;
using System;
using System.IO;

namespace  Arctium.Cryptography.HashFunctions.Hashes
{
    public unsafe class SHA2_256 : HashFunction
    {
        readonly uint[] InitialHashValue = new uint[]
        {
            0x6a09e667,
            0xbb67ae85,
            0x3c6ef372,
            0xa54ff53a,
            0x510e527f,
            0x9b05688c,
            0x1f83d9ab,
            0x5be0cd19
        };

        uint[] currentHashValue;
        uint[] messageScheduleBuffer;
        ByteBufferWithUnsafeCallback blockBuffer;

        public SHA2_256() : base(512, 256)
        {
            currentHashValue = GetInitialHashValue();
            messageScheduleBuffer = new uint[64];

            int bufferSize = HashFunctionsConfig.BufferSizeInBlocks * InputBlockSizeBytes;
            blockBuffer = new ByteBufferWithUnsafeCallback(bufferSize, ExecuteHashing);
        }

        private uint[] GetInitialHashValue()
        {
            uint[] initalValue = new uint[InitialHashValue.Length];

            for (int i = 0; i < InitialHashValue.Length; i++)
            {
                initalValue[i] = InitialHashValue[i];
            }

            return initalValue;
        }

        private void ExecuteHashing(byte* buffer, long length)
        {
            SHA2_224_256_Shared.PerformHashComputation(buffer, length, currentHashValue, messageScheduleBuffer);
        }

        public override void Reset()
        {
            currentHashValue = GetInitialHashValue();
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

            blockBuffer.Load(SHA2_224_256_Shared.GetPadding(LoadedBytes));

            if (blockBuffer.HasData) blockBuffer.FlushBuffer();

            byte[] hash = new byte[32];
            for (int i = 0; i < 8; i++)
            {
                BinConverter.ToBytesBE(hash, i * 4, currentHashValue[i]);
            }

            return hash;
        }
    }
}
