using Arctium.Cryptography.HashFunctions.Hashes.Algorithms;
using Arctium.Cryptography.HashFunctions.Hashes.Configuration;
using Arctium.Shared.Helpers.Buffers;
using System;
using System.IO;

namespace Arctium.Cryptography.HashFunctions.Hashes
{
    //
    // Wrapper for 'Blake3Algorithm' class which holds state and executes 
    // 2 methods: 'Blake3Algorithm.HashLastChunk' and 'Blake3Algorithm.HashFullChunksWhichAreNotTheLast'
    // Second method must be called on the last chunk but input data do not indicates which chunk is last.
    // So, point of the 'cachedChunk' is to hold last loaded data and in 'HashFinal' and call 'HashLastChunk' in 'HashFinal' method.
    //

    public unsafe class BLAKE3 : HashFunction
    {
        const int InputBlockLength = 8192;
        const int HashSizeBlake3 = 256;

        BLAKE3Algorithm.State state;
        byte[] cachedChunk = new byte[1024];
        bool cachedChunkHaveData = false;
        ByteBufferWithUnsafeCallback dataBufferWithCallback;

        public BLAKE3() : base(InputBlockLength, HashSizeBlake3)
        {
            state = new BLAKE3Algorithm.State();
            dataBufferWithCallback = new ByteBufferWithUnsafeCallback(HashFunctionsConfig.BufferSizeInBlocks * InputBlockSizeBytes, ExecuteHashing);
            Reset();
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
            dataBufferWithCallback.Load(buffer, offset, length);
        }

        public unsafe override byte[] HashFinal()
        {
            long dataLength = dataBufferWithCallback.Count;

            if (dataLength == 0 && !cachedChunkHaveData)
            {
                byte* emptyBuffer = stackalloc byte[64];
                return BLAKE3Algorithm.HashLastChunk(emptyBuffer, 1, 0, state);
            }
            else if (dataLength == 0 && cachedChunkHaveData)
            {
                fixed (byte* input = &cachedChunk[0])
                {
                    return BLAKE3Algorithm.HashLastChunk(input, 16, 64, state);
                }
            }

            if (cachedChunkHaveData)
            {
                fixed (byte* input = &cachedChunk[0])
                {
                    BLAKE3Algorithm.HashFullChunksWhichAreNotTheLast(input, 1, state);
                }
            }


            // compute parameters of the last chunk
            long notLastChunksCount = (dataLength - 1) / 1024;
            long lastChunkOffset = notLastChunksCount * 1024;
            long lastChunkLength = dataLength - (notLastChunksCount * 1024);
            long lastChunkLengthWithPadding = RoundUpTo64(lastChunkLength);
            uint lastBlockLength = (uint)lastChunkLength % 64;
            lastBlockLength = lastBlockLength == 0 ? 64 : lastBlockLength;
            byte[] lastChunk = new byte[lastChunkLengthWithPadding];

            MemCpy.Copy(dataBufferWithCallback.Buffer, lastChunkOffset, lastChunk, 0, lastChunkLength);

            if (notLastChunksCount > 0)
            {
                fixed (byte* input = &dataBufferWithCallback.Buffer[0])
                {
                    BLAKE3Algorithm.HashFullChunksWhichAreNotTheLast(input, notLastChunksCount, state);
                }
            }

            fixed (byte* input = &lastChunk[0])
            {
                return BLAKE3Algorithm.HashLastChunk(input, lastChunkLengthWithPadding / 64, lastBlockLength, state);
            }   
        }

        private unsafe void ExecuteHashing(byte* buffer, long length)
        {
            if (cachedChunkHaveData)
            {
                fixed (byte* input = &cachedChunk[0])
                {
                    BLAKE3Algorithm.HashFullChunksWhichAreNotTheLast(input, 1, state);
                }
            }

            long lengthWithoutLastChunk = length - 1024;

            // always store last chunk 
            MemCpy.Copy(buffer + lengthWithoutLastChunk, cachedChunk, 1024);
            cachedChunkHaveData = true;

            if (lengthWithoutLastChunk > 0)
            {
                BLAKE3Algorithm.HashFullChunksWhichAreNotTheLast(buffer, lengthWithoutLastChunk / 1024, state);
            }
        }

        public override void Reset()
        {
            BLAKE3Algorithm.ResetState(state);
            dataBufferWithCallback.Clear();
        }

        private long RoundUpTo64(long value)
        {
            if (value > 0)
            {
                return (((value - 1) / 64) + 1) * 64;
            }
            else return 64;
        }
    }
}
