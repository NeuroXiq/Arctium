using Arctium.Shared;
using System;
using System.Runtime.CompilerServices;
using static Arctium.Shared.BinOps;

namespace Arctium.Cryptography.HashFunctions.Hashes.Algorithms
{
    static unsafe class BLAKE2Algorithm
    {
        static readonly ulong[] BLAKE2bIV = new ulong[]
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

        static readonly uint[] BLAKE2sIV = new uint[]
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

        static readonly uint[][] SIGMA = new uint[][]
        {
            new uint[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
            new uint[] { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
            new uint[] { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
            new uint[] {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
            new uint[] {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
            new uint[] {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
            new uint[] { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
            new uint[] { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
            new uint[] {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
            new uint[] { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
            new uint[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }, // is first row (copy-paste)
            new uint[] { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 } // is second row (copy-paste)
        };

        public class BLAKE2bState
        {
            public ulong[] HashState;
            public ulong HashedBlocks;
        }

        public static BLAKE2bState InitializeHashState_BLAKE2b(ulong outputHashSizeInBytes, ulong keyLength)
        {
            BLAKE2bState state = new BLAKE2bState();
            state.HashedBlocks = 0;
            state.HashState = new ulong[8];
            Array.Copy(BLAKE2bIV, 0, state.HashState, 0, 8);
            state.HashState[0] ^= 0x01010000 ^  (keyLength << 8) ^ (ulong)outputHashSizeInBytes ;

            return state;
        }

        public static void Hash_BLAKE2b(byte* input, ulong inputLength, BLAKE2bState state)
        {
            ulong blocksCount = inputLength / 128;
            ulong* h = stackalloc ulong[8];
            ulong* m = stackalloc ulong[16];
            byte* cInput = input;

            MemCpy.Copy(state.HashState, h);

            for (ulong i = 0; i < blocksCount; i++)
            {
                MemMap.ToULong128BytesLE(cInput, m);

                ++state.HashedBlocks;

                F_BLAKE2b(h, m, (state.HashedBlocks) * 128, false);

                cInput += 128;
            }

            MemCpy.Copy(h, state.HashState);
        }

        public static byte[] GetHashFromState_BLAKE2b(BLAKE2bState state)
        {
            return MemMap.ToByteArrayLE(state.HashState);
        }

        public static void HashLastBlock_BLAKE2b(byte* input, ulong fullMessageLengthWithoutPadding, BLAKE2bState state)
        {
            ulong* h = stackalloc ulong[8];
            ulong* m = stackalloc ulong[16];
            byte* cInput = input;

            MemCpy.Copy(state.HashState, h);
            MemMap.ToULong128BytesLE(cInput, m);

            //++state.HashedBlocks;
            // same as Hash but 'true' param
            F_BLAKE2b(h, m, fullMessageLengthWithoutPadding, true);

            MemCpy.Copy(h, state.HashState);
        }

        static void F_BLAKE2b(ulong* h, ulong* m, ulong t, bool f)
        {
            uint[] s;
            ulong* v = stackalloc ulong[16];
            MemCpy.Copy8ULong(h, v);
            MemCpy.Copy(BLAKE2bIV, v + 8);

            v[12] ^= t;
            v[13] ^= (0); // assumes that input neved exceed long 

            if (f)
            {
                v[14] ^= 0xFFFFFFFFFFFFFFFF;
            }

            for (int i = 0; i < 12; i++)
            {
                s = SIGMA[i];
                
                G_BLAKE2b(v, 0, 4,  8, 12, m[s[0]], m[s[1]]);
                G_BLAKE2b(v, 1, 5,  9, 13, m[s[2]], m[s[3]]);
                G_BLAKE2b(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
                G_BLAKE2b(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);

                G_BLAKE2b(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
                G_BLAKE2b(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
                G_BLAKE2b(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
                G_BLAKE2b(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
            }

            for (int i = 0; i < 8; i++)
            {
                h[i] ^= v[i] ^ v[i + 8];
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        static void G_BLAKE2b(ulong* v, int a, int b, int c, int d, ulong x, ulong y)
        {
            v[a] = v[a] + v[b] + x;
            v[d] = ROR(v[d] ^ v[a], 32);
            v[c] = v[c] + v[d];
            v[b] = ROR(v[b] ^ v[c], 24);
            v[a] = v[a] + v[b] + y;
            v[d] = ROR(v[d] ^ v[a], 16);
            v[c] = v[c] + v[d];
            v[b] = ROR(v[b] ^ v[c], 63);
        }

        //[MethodImpl(MethodImplOptions.AggressiveInlining)]
        //static void G_BLAKE2s(uint* v, int a, int b, int c, int d, uint x, uint y)
        //{
        //    v[a] = v[a] + v[b] + x;
        //    v[d] = ROR(v[d] ^ v[a], 16);
        //    v[c] = v[c] + v[d];
        //    v[b] = ROR(v[b] ^ v[c], 12);
        //    v[a] = v[a] + v[b] + y;
        //    v[d] = ROR(v[b] ^ v[a], 8);
        //    v[c] = v[c] + v[d];
        //    v[b] = ROR(v[b] ^ v[c], 7);
        //}
    }
}
