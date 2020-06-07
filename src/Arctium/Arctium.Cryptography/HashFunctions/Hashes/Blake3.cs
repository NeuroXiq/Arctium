using Arctium.Cryptography.HashFunctions.Hashes.Algorithms;
using Arctium.Shared.Helpers.Buffers;
using System;

namespace Arctium.Cryptography.HashFunctions.Hashes
{
    //
    // Wrapper for 'Blake3Algorithm' class which holds state and executes 
    // 2 methods: 'Blake3Algorithm.HashLastChunk' and 'Blake3Algorithm.HashFullChunksWhichAreNotTheLast'
    // Second method must be called on the last chunk but input data do not indicates which chunk is last.
    // So, point of the 'cachedChunk' is to hold last loaded data and in 'HashFinal' and call 'HashLastChunk' in 'HashFinal' method.
    //

    public class Blake3 : HashFunctionBase
    {
        const int InputBlockLength = 8192;
        const int HashSizeBlake3 = 256;

        Blake3Algorithm.State state;
        byte[] cachedChunk = new byte[1024];
        bool cachedChunkHaveData = false;

        public Blake3() : base(InputBlockLength, HashSizeBlake3)
        {
            state = new Blake3Algorithm.State();
            ResetCurrentState();
        }

        public unsafe override byte[] HashFinal()
        {
            if (hashFinalCalled) throw new InvalidOperationException("Has final was called. Must reset state");
            hashFinalCalled = true;

            long dataLength = dataBufferWithCallback.Count;

            if (dataLength == 0 && !cachedChunkHaveData)
            {
                byte* emptyBuffer = stackalloc byte[64];
                return Blake3Algorithm.HashLastChunk(emptyBuffer, 1, 0, state);
            }
            else if (dataLength == 0 && cachedChunkHaveData)
            {
                fixed (byte* input = &cachedChunk[0])
                {
                    return Blake3Algorithm.HashLastChunk(input, 16, 64, state);
                }
            }

            if (cachedChunkHaveData)
            {
                fixed (byte* input = &cachedChunk[0])
                {
                    Blake3Algorithm.HashFullChunksWhichAreNotTheLast(input, 1, state);
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
                    Blake3Algorithm.HashFullChunksWhichAreNotTheLast(input, notLastChunksCount, state);
                }
            }

            fixed (byte* input = &lastChunk[0])
            {
                return Blake3Algorithm.HashLastChunk(input, lastChunkLengthWithPadding / 64, lastBlockLength, state);
            }   
        }

        protected override unsafe void ExecuteHashing(byte* buffer, long length)
        {
            if (cachedChunkHaveData)
            {
                fixed (byte* input = &cachedChunk[0])
                {
                    Blake3Algorithm.HashFullChunksWhichAreNotTheLast(input, 1, state);
                }
            }

            long lengthWithoutLastChunk = length - 1024;

            // always store last chunk 
            MemCpy.Copy(buffer + lengthWithoutLastChunk, cachedChunk, 1024);
            cachedChunkHaveData = true;

            if (lengthWithoutLastChunk > 0)
            {
                Blake3Algorithm.HashFullChunksWhichAreNotTheLast(buffer, lengthWithoutLastChunk / 1024, state);
            }
        }

        protected override byte[] GetCurrentHash()
        {
            throw new InvalidOperationException("Overloaded in hash final");
        }

        protected override byte[] GetPadding()
        {
            throw new InvalidOperationException("Padding created in hash final");
        }

        protected override void ResetCurrentState()
        {
            Blake3Algorithm.ResetState(state);
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
