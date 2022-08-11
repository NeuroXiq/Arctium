using Arctium.Cryptography.HashFunctions.Hashes.Algorithms;

using Arctium.Shared.Helpers.Binary;
using Arctium.Shared.Helpers.Buffers;
using System;
using System.IO;

namespace  Arctium.Cryptography.HashFunctions.Hashes
{
    public unsafe class SHA2_224 : HashFunction
    {
        uint[] InitialHashValue = new uint[]
        {
            0xc1059ed8,
            0x367cd507,
            0x3070dd17,
            0xf70e5939,
            0xffc00b31,
            0x68581511,
            0x64f98fa7,
            0xbefa4fa4
        };

        //represents eigth 32-bit words
        uint[] hashValue;
        uint[] messageScheduleBuffer;
        ByteBufferWithUnsafeCallback blockBuffer;

        public SHA2_224() : base(512, 224)
        {
            hashValue = GetInitialHashValue();
            messageScheduleBuffer = new uint[64];
            int bufferSize = HashFunctionsConfig.BufferSizeInBlocks * InputBlockSizeBytes;
            blockBuffer = new ByteBufferWithUnsafeCallback(bufferSize, ExecuteHashing);
        }

        private void ExecuteHashing(byte* buffer, long length)
        {
            SHA2_224_256_Shared.PerformHashComputation(buffer, length, hashValue, messageScheduleBuffer);
        }

        private uint[] GetInitialHashValue()
        {
            uint[] initialValue = new uint[InitialHashValue.Length];
            for (int i = 0; i < initialValue.Length; i++)
            {
                initialValue[i] = InitialHashValue[i];
            }

            return initialValue;
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
            byte[] result = new byte[28];
            blockBuffer.Load(SHA2_224_256_Shared.GetPadding(LoadedBytes));

            if (blockBuffer.HasData) blockBuffer.FlushBuffer();

            for (int i = 0; i < 7; i++)
            {
                BinConverter.ToBytesBE(result, i * 4, hashValue[i]);
            }

            return result;
        }
    }
}
