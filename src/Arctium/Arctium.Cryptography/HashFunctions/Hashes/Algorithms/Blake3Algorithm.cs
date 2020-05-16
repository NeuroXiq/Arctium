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

        public struct State
        {
            public uint* h;
            public long processed64BytesBlocks;
        }

        public static void SetStateToInitial(State* state)
        {
            state->processed64BytesBlocks = 0;

            for (int i = 0; i < 8; i++)
                state->h[0] = IVConstants[i];


        }

        public static void HashBytes(byte* input, long length, State* state)
        {

        }


        static void CompressionFunction(byte* inputMessage, uint* h, uint* output)
        {
            uint* inputUints = stackalloc uint[16];
            MemMap.ToUInt64BytesLE(inputMessage, inputUints);

            // initialize state
            uint* v = stackalloc uint[16];

            // 
            MemCpy.Copy8Uint(h, v);

            v[8] = 0x6a09e667;
            v[9] = 0xbb67ae85;
            v[10] = 0x3c6ef372;
            v[11] = 0xa54ff53a;


            uint* input = inputUints;
            uint* permute = stackalloc uint[16];


            for (int i = 0; i < 7; i++)
            {
                G(&v[0], &v[4], &v[8], &v[12], input[(2 * i)], input[(2 * i) + 1]);
                G(&v[1], &v[5], &v[9], &v[13], input[(2 * i)], input[(2 * i) + 1]);
                G(&v[2], &v[6], &v[10], &v[14], input[(2 * i)], input[(2 * i) + 1]);
                G(&v[3], &v[7], &v[11], &v[15], input[(2 * i)], input[(2 * i) + 1]);

                G(&v[0], &v[5], &v[10], &v[15], input[(2 * i)], input[(2 * i) + 1]);
                G(&v[1], &v[6], &v[11], &v[12], input[(2 * i)], input[(2 * i) + 1]);
                G(&v[2], &v[7], &v[8], &v[13], input[(2 * i)], input[(2 * i) + 1]);
                G(&v[3], &v[4], &v[9], &v[14], input[(2 * i)], input[(2 * i) + 1]);

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
