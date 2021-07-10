
using System.IO;
using Arctium.Cryptography.HashFunctions.Hashes.Algorithms;
using Arctium.Cryptography.HashFunctions.Hashes.Configuration;
using Arctium.Shared.Helpers.Binary;
using Arctium.Shared.Helpers.Buffers;

namespace  Arctium.Cryptography.HashFunctions.Hashes
{
    public unsafe class SHA2_384 : HashFunction
    {
        static readonly ulong[] InitialHashValue = new ulong[] 
        {
            0xcbbb9d5dc1059ed8,
            0x629a292a367cd507,
            0x9159015a3070dd17,
            0x152fecd8f70e5939,
            0x67332667ffc00b31,
            0x8eb44a8768581511,
            0xdb0c2e0d64f98fa7,
            0x47b5481dbefa4fa4
        };

        ulong[] hashValue;
        ulong[] messageScheduleBuffer;
        ByteBufferWithUnsafeCallback blockBuffer;

        public SHA2_384() : base(1024, 384)
        {
            hashValue = GetInitialHashValue();
            int bufferSize = HashFunctionsConfig.BufferSizeInBlocks * InputBlockSizeBytes;
            blockBuffer = new ByteBufferWithUnsafeCallback(bufferSize, ExecuteHashing);
            messageScheduleBuffer = new ulong[80];
        }

        private ulong[] GetInitialHashValue()
        {
            ulong[] initial = new ulong[8];
            InitialHashValue.CopyTo(initial, 0);

            return initial;
        }

        protected void ExecuteHashing(byte* buffer, long length)
        {
            SHA2_384_512_Shared.PerformHashComputation(hashValue, buffer,  length, messageScheduleBuffer);
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

            byte[] result = new byte[48];

            for (int i = 0; i < 6; i++)
            {
                BinConverter.ToBytesBE(result, i * 8, hashValue[i]);
            }

            return result;
        }
    }
}
