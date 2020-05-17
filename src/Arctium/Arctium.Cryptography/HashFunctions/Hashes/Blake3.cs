using Arctium.Cryptography.HashFunctions.Hashes.Algorithms;
using System;

namespace Arctium.Cryptography.HashFunctions.Hashes
{
    public class Blake3 : HashFunctionBase
    {
        const int InputBlockLength = 8192;
        const int HashSize = 256;
        const int ChunkLength = 1024;

        Blake3Algorithm.State state;
        uint[] h;

        public Blake3() : base(InputBlockLength, HashSize)
        {
            state = new Blake3Algorithm.State();
            ResetCurrentState();
        }

        public override byte[] HashFinal()
        {
            long dataLength = dataBufferWithCallback.Count;

            long lengthWithPadding = 0;
            if (CurrentMessageLengthWithoutPadding > 0)
            {
                // round to 64 bytes
                lengthWithPadding = ((CurrentMessageLengthWithoutPadding - 1) / 64) + 1;
                lengthWithPadding *= 64;
            }
            else
            {
                lengthWithPadding = 64;
            }


            byte[] lastBytes = new byte[lengthWithPadding];
            dataBufferWithCallback.CopyTo(lastBytes, 0);

            unsafe
            {
                fixed (byte* lastBlockPtr = &lastBytes[0])
                {
                    Blake3Algorithm.HashLastBlocks(lastBlockPtr, lengthWithPadding, CurrentMessageLengthWithoutPadding, state);
                }
            }

            return new byte[0];
        }

        protected override unsafe void ExecuteHashing(byte* buffer, long length)
        {
            //long lastChunkLength = base.CurrentMessageLengthWithoutPadding % ChunkLength;
            //Blake3Algorithm.HashBytes(buffer, 
        }

        protected override byte[] GetCurrentHash()
        {
            throw new NotImplementedException();
        }

        protected override byte[] GetPadding()
        {
            throw new NotImplementedException();
            long paddingLength = CurrentMessageLengthWithoutPadding % 64;
            if (CurrentMessageLengthWithoutPadding == 0)
                paddingLength = 64;
            return new byte[paddingLength];
        }

        protected override void ResetCurrentState()
        {
            Blake3Algorithm.ResetState(state);
        }
    }
}
