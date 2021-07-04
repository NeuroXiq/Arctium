using Arctium.Cryptography.HashFunctions.Hashes.Algorithms;
using Arctium.Cryptography.HashFunctions.Hashes.Configuration;
using Arctium.Cryptography.HashFunctions.Hashes.HashHelpers;
using Arctium.Shared.Helpers.Buffers;
using System;
using System.IO;

namespace Arctium.Cryptography.HashFunctions.Hashes
{
    public unsafe abstract class BLAKE2b : HashFunction
    {
        public const int BLAKE2bInputBlockSize = 8192;

        private const int InputBlockSizeInBytes = 128;

        private BLAKE2Algorithm.BLAKE2bState state;

        private BlockCache lastBlockCache;

        ByteBufferWithUnsafeCallback dataBufferWithCallback;

        protected BLAKE2b(int hashSize) : base(BLAKE2bInputBlockSize, hashSize)
        {
            lastBlockCache = new BlockCache(InputBlockSizeInBytes);
            dataBufferWithCallback = new ByteBufferWithUnsafeCallback(HashFunctionsConfig.BufferSizeInBlocks * InputBlockSizeBytes, ExecuteHashing);
            Reset();
        }

        public override byte[] HashFinal()
        {
            // This is little tricky because BLAKE2 require to determine,
            // which block is the last one. So, lastBlockCache always store
            // 128-bytes of input data that need to be hashed.

            if (!lastBlockCache.HaveData && dataBufferWithCallback.Count == 0)
            {
                // no any data, just hash 0-filled 128-byte block
                byte* emptyBuffer = stackalloc byte[128];
                BLAKE2Algorithm.HashLastBlock_BLAKE2b(emptyBuffer, 0, state);
            }
            else if (lastBlockCache.HaveData && dataBufferWithCallback.Count == 0)
            {
                // provided exactly 128-bytes input bytes 
                fixed (byte* input = &lastBlockCache.Buffer[0])
                {
                    BLAKE2Algorithm.HashLastBlock_BLAKE2b(input, 128, state);
                }
            }
            else
            {
                if (lastBlockCache.HaveData)
                {
                    fixed (byte* input = &lastBlockCache.Buffer[0])
                    {
                        BLAKE2Algorithm.Hash_BLAKE2b(input, 128, state);
                    }
                }

                byte* lastBlock = stackalloc byte[128];
                long lastBlockOffset = ((dataBufferWithCallback.Count - 1) / 128) * 128;
                long lastBlockLength = dataBufferWithCallback.Count % 128;

                if (lastBlockLength == 0)
                {
                    // exactly aligned, so need to take full 128-bytes
                    lastBlockLength = 128;
                }

                MemCpy.Copy(dataBufferWithCallback.Buffer, lastBlockOffset, lastBlock, 0, lastBlockLength);

                // hash not last block
                if (lastBlockOffset > 0)
                {
                    fixed (byte* input = &dataBufferWithCallback.Buffer[0])
                    {
                        BLAKE2Algorithm.Hash_BLAKE2b(input, (ulong)lastBlockOffset, state);
                    }
                }

                // finally, hash last block
                BLAKE2Algorithm.HashLastBlock_BLAKE2b(lastBlock, (ulong)LoadedBytes, state);
            }

            byte[] hash = BLAKE2Algorithm.GetHashFromState_BLAKE2b(state);
            lastBlockCache.ClearData();

            return hash;
        }

        protected unsafe void ExecuteHashing(byte* buffer, long length)
        {
            if (lastBlockCache.HaveData)
            {
                fixed (byte* input = &lastBlockCache.Buffer[0])
                {
                    BLAKE2Algorithm.Hash_BLAKE2b(input, InputBlockSizeInBytes, state);
                }
            }

            long lengthWithoutLastBlock = length - InputBlockSizeInBytes;
            lastBlockCache.SetData(buffer, lengthWithoutLastBlock);

            if (lengthWithoutLastBlock > 0)
            {
                BLAKE2Algorithm.Hash_BLAKE2b(buffer, (ulong)lengthWithoutLastBlock, state);
            }
        }

        public override void HashBytes(byte[] buffer)
        {
            LoadedBytes += dataBufferWithCallback.Load(buffer);
        }

        public override long HashBytes(Stream stream)
        {
            long loaded = dataBufferWithCallback.Load(stream);

            LoadedBytes += loaded;

            return loaded;
        }

        public override void HashBytes(byte[] buffer, long offset, long length)
        {
            LoadedBytes += dataBufferWithCallback.Load(buffer, offset, length);
        }

        protected byte[] GetPadding()
        {
            if (LoadedBytes == 0)
            {
                return new byte[128];
            }

            long padding = LoadedBytes % 128;

            return padding > 0 ? new byte[padding] : null;
        }

        public override void Reset()
        {
            state = BLAKE2Algorithm.InitializeHashState_BLAKE2b((ulong)HashSizeBytes, 0);
            dataBufferWithCallback.Clear();
            lastBlockCache.ClearData();
            LoadedBytes = 0;
        }
    }
}
