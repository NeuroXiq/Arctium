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
using static Arctium.Shared.Helpers.Binary.BinOps;

namespace Arctium.Cryptography.Ciphers.BlockCiphers.Serpent
{
    public static unsafe class SerpentAlgorithm
    {
        // 0-15 S0
        // 16-31 S1 etc..

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

        /// <summary>
        /// 
        /// </summary>
        /// <param name="input"></param>
        /// <param name="output">output array of 33 uint (schedule key)</param>
        public static void KeySchedule(byte* input, uint* output)
        {
            uint* w = stackalloc uint[140];
            uint* prekey = w + 8;

            //MemMap.ToUInt32BytesLE(input, w);
            
            for (int i = 0; i < 8; i++)
            {
                w[i] = BinConverter.ToUIntBE(input, i * 4);
            }

            for (uint i = 0; i < 132; i++)
            {
                prekey[i] = prekey[i - 8] ^ prekey[i - 5] ^ prekey[i - 3] ^ prekey[i - 1] ^ 0x9e3779b9 ^ (i);
                prekey[i] = BinOps.ROL(prekey[i], 11);
            }

            int mod8 = 7;
            uint* block128Bits = prekey;
            for (int i = 0; i < 33; i++)
            {   
                int sboxNo = (3 - (i - 8)) & mod8;
                ApplySBox(block128Bits, block128Bits, sboxNo);
                block128Bits += 4;
            }

            MemCpy.Copy(prekey, output, 33);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="input"></param>
        /// <param name="skey">33 uint array of encryption key (after keySchedule)</param>
        /// <param name="output"></param>
        public static void EncryptBlock(byte* input,uint* skey, byte* output)
        {
            uint* x = stackalloc uint[4];
            x[0] = BinConverter.ToUIntLE(input + 0);
            x[1] = BinConverter.ToUIntLE(input + 4);
            x[2] = BinConverter.ToUIntLE(input + 8);
            x[3] = BinConverter.ToUIntLE(input + 12);

            int keyRoundIndex = 0;

            for (int i = 0; i < 32; i++)
            {
                x[0] ^= skey[keyRoundIndex + 0];
                x[1] ^= skey[keyRoundIndex + 1];
                x[2] ^= skey[keyRoundIndex + 2];
                x[3] ^= skey[keyRoundIndex + 3];

                ApplySBox(x, x, i % 8);

                x[0] = ROL(x[0], 13);
                x[2] = ROL(x[2], 3);
                x[1] = x[1] ^ x[0] ^ x[2];
                x[3] = x[3] ^ x[2] ^ (uint)(x[0] << 3);
                x[1] = ROL(x[1], 1);
                x[3] = ROL(x[3], 7);
                x[0] = x[0] ^ x[1] ^ x[3];
                x[2] = x[2] ^ x[3] ^ (x[1] << 7);
                x[0] = ROL(x[0], 5);
                x[2] = ROL(x[2], 22);

                MemDump.HexDump(x, 4);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ApplySBox(uint* inputBlock128Bits, uint* outputBlock128Bits, int sboxStartIndex)
        {
            sboxStartIndex *= 16;

            uint y0=0, y1=0, y2=0, y3=0;

            for (int i = 0; i < 32; i++)
            {
                uint sboxKey = 0;

                sboxKey =  ((inputBlock128Bits[0] >> i) & 0x01);
                sboxKey |= ((inputBlock128Bits[1] >> i) & 0x01) << 1;
                sboxKey |= ((inputBlock128Bits[2] >> i) & 0x01) << 2;
                sboxKey |= ((inputBlock128Bits[3] >> i) & 0x01) << 3;

                byte sboxValue = SBox[(int)sboxKey + sboxStartIndex];
                
                y0 |= (uint)((sboxValue >> 0) & 1) << i;
                y1 |= (uint)((sboxValue >> 1) & 1) << i;
                y2 |= (uint)((sboxValue >> 2) & 1) << i;
                y3 |= (uint)((sboxValue >> 3) & 1) << i;
            }

            outputBlock128Bits[0] = y0;
            outputBlock128Bits[1] = y1;
            outputBlock128Bits[2] = y2;
            outputBlock128Bits[3] = y3;
        }
    }
}
