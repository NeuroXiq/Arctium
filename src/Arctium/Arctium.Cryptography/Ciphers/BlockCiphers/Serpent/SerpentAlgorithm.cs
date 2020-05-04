/*
 * Serpent algorithm 
 * Algorithms authors: Ross Anderson, Eli Biham, Lars Knudsen
 *
 * Implemented by NeuroXiq
 * https://github.com/NeuroXiq/
 */

using Arctium.Shared.Helpers.Binary;
using Arctium.Shared.Helpers.Buffers;
using System.Runtime.CompilerServices;

namespace Arctium.Cryptography.Ciphers.BlockCiphers.Serpent
{
    public static unsafe class SerpentAlgorithm
    {
        private static byte[] SBox = new byte[] {
            3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12,
            15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4,
            8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2,
            0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14,
            1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13,
            15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1,
            7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0,
            1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6, };

        private static byte[] InvSBox = new byte[] {
             13, 3, 11, 0, 10, 6, 5, 12, 1, 14, 4, 7, 15, 9, 8, 2,
             5, 8, 2, 14, 15, 6, 12, 3, 11, 4, 7, 9, 1, 13, 10, 0,
             12, 9, 15, 4, 11, 14, 1, 2, 0, 3, 6, 13, 5, 8, 10, 7,
             0, 9, 10, 7, 11, 14, 6, 13, 3, 5, 12, 2, 4, 8, 15, 1,
             5, 0, 8, 3, 10, 9, 7, 14, 2, 12, 11, 6, 4, 15, 13, 1,
             8, 15, 2, 9, 4, 1, 13, 14, 11, 6, 5, 3, 7, 12, 10, 0,
             15, 10, 1, 13, 5, 3, 6, 0, 4, 9, 14, 7, 2, 12, 8, 11,
             3, 0, 6, 13, 9, 14, 15, 8, 5, 12, 11, 7, 10, 1, 4, 2,
        };

        public static void KeySchedule(byte* input, uint* output)
        {
            uint* w = stackalloc uint[140];
            MemMap.ToUInt32BytesLE(input, w);

            for (uint i = 8; i < 140; i++)
            {
                w[i] = w[i - 8] ^ w[i - 5] ^ w[i - 3] ^ w[i - 1] ^ 0x9e3779b9 ^ i;
                w[i] = BinOps.ROL32(w[i], 11);
            }


            for (int i = 8; i < 140; i++)
            {

            }

        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint SBoxTransform(uint value, uint sboxStartIndex)
        {
            uint result = 0;

            for (int i = 0; i < 8; i++)
            {
                uint idx = (value >> (i * 4)) & 0xF;
                result |= (SBox[idx + (16 * sboxStartIndex)]);
            }

            return result;
        }
    }
}
