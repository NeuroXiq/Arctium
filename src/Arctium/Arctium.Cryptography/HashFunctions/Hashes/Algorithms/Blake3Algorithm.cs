using Arctium.Shared.Helpers.Buffers;
using System.Runtime.CompilerServices;
using static Arctium.Shared.Helpers.Binary.BinOps;

namespace Arctium.Cryptography.HashFunctions.Hashes.Algorithms
{
    static unsafe class Blake3Algorithm
    {
        enum Flags
        {
            ChunkStart = 1 << 0,
            ChunkEnd = 1 << 1,
            Parent = 1 << 2,
            Root = 1 << 3,
            KeyedHash = 1 << 4,
            DeriveKeyContext = 1 << 5,
            DeriveKeyMaterial = 1 << 6
        };

        const uint FlagChunkStart = 1 << 0;
        const uint FlagChunkEnd = 1 << 1;
        const uint FlagParent = 1 << 2;
        const uint FlagRoot = 1 << 3;
        const uint FlagKeyedHash = 1 << 4;
        const uint FlagDeriveKeyContext = 1 << 5;
        const uint FlagDeriveKeyMaterial = 1 << 6;

        static readonly uint[] IVConstants = new uint[] {
            0x6a09e667,
            0xbb67ae85,
            0x3c6ef372,
            0xa54ff53a,
            0x510e527f,
            0x9b05688c,
            0x1f83d9ab,
            0x5be0cd19
        };

        public class State
        {
            public uint[] h;
            public long counter;
        }

        public static void ResetState(State state)
        {
            state.counter = 0;
            if(state.h == null) state.h = new uint[8];

            for (int i = 0; i < 8; i++)
                state.h[i] = IVConstants[i];
        }

        public static void HashFullChunks(byte* input, long inputLength, State state)
        {
            uint* inputBuffer = stackalloc uint[16];
            uint* outputBuffer = stackalloc uint[16];

            long remainingBlocks = inputLength / 64;

            uint flags = 0;
            long bytesInChunk = 0;
            long counter = state.counter;

            while (remainingBlocks > 16)
            {
                MemMap.ToUInt64BytesLE(input, inputBuffer);
                for (int i = 0; i < 16; i++)
                {

                }

                counter++;
                remainingBlocks -= 16;
            }
        }

        public static void HashLastBlocks(byte* input, long inputLength, long dataLength, State state)
        {
            uint* inputBuffer = stackalloc uint[16];
            uint* outputBuffer = stackalloc uint[16];

            uint blocksCount = (uint)(inputLength / 64);

            uint flags = 0;
            uint bytesInChunk = 0;
            long counter = state.counter;

            for(int i = 0; i < blocksCount; i++)
            {
                MemMap.ToUInt64BytesLE(input, inputBuffer);
                flags = 0;
                bytesInChunk = 64;

                if (i == 0)
                {
                    flags |= FlagChunkStart;
                }
                if (i == blocksCount - 1)
                {
                    flags |= FlagChunkEnd;
                    // test
                    // this work, need to check when to set this flag
                    flags |= FlagRoot;
                    //tetsend
                    bytesInChunk = (uint)dataLength - (64 * (blocksCount - 1));
                }
                
                CompressionFunction(inputBuffer, state.h, counter, bytesInChunk, flags, outputBuffer);

                input += 64;
            }

            MemDump.HexDump(outputBuffer, 16);
        }


        static void CompressionFunction(uint* input, uint[] h, long counter, uint blockLength, uint flags, uint* output)
        {
            // initialize state
            uint* v = stackalloc uint[16];

            // TODO can be removed  and put state directly in State
            for (int i = 0; i < 8; i++) v[i] = h[i];

            v[8] = 0x6a09e667;
            v[9] = 0xbb67ae85;
            v[10] = 0x3c6ef372;
            v[11] = 0xa54ff53a;
            v[12] = (uint)counter;
            v[13] = (uint)(counter >> 32);
            v[14] = blockLength;
            v[15] = flags;

            uint* permute = stackalloc uint[16];

            for (int i = 0; i < 7; i++)
            {
                G(&v[0], &v[4], &v[8], &v[12],  input[0], input[1]);
                G(&v[1], &v[5], &v[9], &v[13],  input[2], input[3]);
                G(&v[2], &v[6], &v[10], &v[14], input[4], input[5]);
                G(&v[3], &v[7], &v[11], &v[15], input[6], input[7]);

                G(&v[0], &v[5], &v[10], &v[15], input[8],  input[9]);
                G(&v[1], &v[6], &v[11], &v[12], input[10], input[11]);
                G(&v[2], &v[7], &v[8], &v[13],  input[12], input[13]);
                G(&v[3], &v[4], &v[9], &v[14],  input[14], input[15]);

                for (int j = 0; j < 16; j++)
                {
                    permute[i] = input[permuteInOut[j]];
                }

                uint** swapCpy = &input;
                input = permute;
                permute = *swapCpy;
            }


            // output

            output[0] = v[0] ^ v[8];
            output[1] = v[1] ^ v[9];
            output[2] = v[2] ^ v[10];
            output[3] = v[3] ^ v[11];
            output[4] = v[4] ^ v[12];
            output[5] = v[5] ^ v[13];
            output[6] = v[6] ^ v[14];
            output[7] = v[7] ^ v[15];

            output[8]  = v[8]  ^ h[0];
            output[9]  = v[9]  ^ h[1];
            output[10] = v[10] ^ h[2];
            output[11] = v[11] ^ h[3];
            output[12] = v[12] ^ h[4];
            output[13] = v[13] ^ h[5];
            output[14] = v[14] ^ h[6];
            output[15] = v[15] ^ h[7];
        }


        static uint[] gInputIndexes = new uint[]
        {
            0,4,8,12,
            1,5,9,13,
            2,6,10,14,
            3,7,11,15,

            0,5,10,15,
            1,6,11,12,
            2,7,8,13,
            3,4,9,14
        };

        static uint[] permuteInOut = new uint[]
        {
            2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8
        };

        /// <summary>
        /// Quater round, 
        /// </summary>
        /// <param name="q"></param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        static void G(uint* inOuta, uint* inOutb, uint* inOutc, uint* inOutd, uint m0, uint m1)
        {
            uint a = *inOuta;
            uint b = *inOutb;
            uint c = *inOutc;
            uint d = *inOutd;

            a = a + b + m0;
            d = ROR(d ^ a, 16);
            c = c + d;
            b = ROR(b ^ c, 12);
            a = a + b + m1;
            d = ROR(d ^ a, 8);
            c = c + d;
            b = ROR(b ^ c, 7);

            *inOuta = a;
            *inOutb = b;
            *inOutc = c;
            *inOutd = d;
        }
    }
}
