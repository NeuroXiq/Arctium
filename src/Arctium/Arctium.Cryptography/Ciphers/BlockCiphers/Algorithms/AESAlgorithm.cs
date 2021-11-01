/* Advanced Encryption Standard (AES) algorithm
 * FIPS 197
 * Authors: Vincent Rijmen, Joan Daemen
 * 
 * ----------------------------------------
 * 
 */

using System;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Shared.Helpers.Binary;

namespace Arctium.Cryptography.Ciphers.BlockCiphers.Algorithms
{
    public static unsafe class AESAlgorithm
    {
        const int RoundsCount128 = 10;
        const int RoundsCount192 = 12;
        const int RoundsCount256 = 14;
        const int BlockSizeWords = 4;

        static uint[] Rcon = new uint[]
        {
           0x01000000, 
           0x02000000, 
           0x04000000, 
           0x08000000, 
           0x10000000, 
           0x20000000, 
           0x40000000, 
           0x80000000, 
           0x1b000000, 
           0x36000000 
        };

        static byte[] sbox = new byte[]
        {
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        };

        static byte[] inverseSbox = new byte[]
        {
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
        };

        public class Context
        {
            public uint[] ExpandedKey;
        }

        public static Context Initialize(byte[] key)
        {
            Context context = new Context();
            Reset(context, key);

            return context;
        }

        public static void Reset(Context context, byte[] key)
        {
            if (context.ExpandedKey == null) context.ExpandedKey = new uint[(RoundsCount(key.Length) + 1) * 4];
            
            ExpandKey(key, context.ExpandedKey);
        }

        public static void DecryptSingleBlock(Context context, byte* input, long inOffset, byte* output, long outOffset, int rounds)
        {
            byte* state = stackalloc byte[16];
            
            MapStateBytes(input + inOffset, state);

            AddRoundKey(state, context.ExpandedKey, rounds);

            for (int i = rounds - 1; i >= 1; i--)
            {
                InvShiftRows(state);
                InvSubBytes(state);
                AddRoundKey(state, context.ExpandedKey, i);
                InvMixColumns(state);
            }

            InvShiftRows(state);
            InvSubBytes(state);
            AddRoundKey(state, context.ExpandedKey, 0);

            MapStateBytes(state, output + outOffset);
        }

        static void InvShiftRows(byte* state)
        {
            uint t1, t2, t3;
            t1 = MemMap.ToNewUInt4BytesBE(state, 4);
            t2 = MemMap.ToNewUInt4BytesBE(state, 8);
            t3 = MemMap.ToNewUInt4BytesBE(state, 12);

            t1 = BinOps.ROR(t1, 8);
            t2 = BinOps.ROR(t2, 16);
            t3 = BinOps.ROR(t3, 24);

            MemMap.ToBytes1UIntBE(t1, state, 4);
            MemMap.ToBytes1UIntBE(t2, state, 8);
            MemMap.ToBytes1UIntBE(t3, state, 12);
        
        }

        static void InvSubBytes(byte* state)
        {
            for (int i = 0; i < 16; i++) state[i] = inverseSbox[state[i]];
        }

        static void InvMixColumns(byte* state)
        {
            byte s0,s1,s2,s3,r0,r1,r2,r3;

            for (int i = 0; i < 4; i++)
            {
                s0 = state[i + (4 * 0)];
                s1 = state[i + (4 * 1)];
                s2 = state[i + (4 * 2)];
                s3 = state[i + (4 * 3)];

                r0 = (byte)(GFMul(0x0E, s0) ^ GFMul(0x0B, s1) ^ GFMul(0x0D, s2) ^ GFMul(0x09, s3));
                r1 = (byte)(GFMul(0x09, s0) ^ GFMul(0x0E, s1) ^ GFMul(0x0B, s2) ^ GFMul(0x0D, s3));
                r2 = (byte)(GFMul(0x0D, s0) ^ GFMul(0x09, s1) ^ GFMul(0x0E, s2) ^ GFMul(0x0B, s3));
                r3 = (byte)(GFMul(0x0B, s0) ^ GFMul(0x0D, s1) ^ GFMul(0x09, s2) ^ GFMul(0x0E, s3));

                state[i + (4 * 0)] = r0;
                state[i + (4 * 1)] = r1;
                state[i + (4 * 2)] = r2;
                state[i + (4 * 3)] = r3;
            }
        }

        public static void EncryptSingleBlock(Context context, byte* input, long inOffset, byte* output, long outOffset, int rounds)
        {
            byte* state = stackalloc byte[16];

            for (long i = 0; i < 4; i++)
            {
                state[0 + (i * 4)] = input[inOffset + i + 0];
                state[1 + (i * 4)] = input[inOffset + i + 4];
                state[2 + (i * 4)] = input[inOffset + i + 8];
                state[3 + (i * 4)] = input[inOffset + i + 12];
            }

            AddRoundKey(state, context.ExpandedKey, 0);

            for (int i = 1; i <= rounds - 1; i++)
            {
                SubBytes(state);
                ShiftRows(state);
                MixColumns(state);
                AddRoundKey(state, context.ExpandedKey, i);
            }

            SubBytes(state);
            ShiftRows(state);
            AddRoundKey(state, context.ExpandedKey, rounds);

            for (long i = 0; i < 4; i++)
            {
                output[0 + (i * 4) + outOffset] = state[i + 0];
                output[1 + (i * 4) + outOffset] = state[i + 4];
                output[2 + (i * 4) + outOffset] = state[i + 8];
                output[3 + (i * 4) + outOffset] = state[i + 12];
            }
        }

        // Private
        
        static void MapStateBytes(byte* input, byte* output)
        {
            for (int i = 0; i < 4; i++)
            {
               output[i +  0] = input[(i * 4) + 0]; 
               output[i +  4] = input[(i * 4) + 1]; 
               output[i +  8] = input[(i * 4) + 2]; 
               output[i + 12] = input[(i * 4) + 3]; 
            } 
        }

        static void ShiftRows(byte* state)
        {
            uint t1, t2, t3;
            t1 = MemMap.ToNewUInt4BytesBE(state, 4);
            t2 = MemMap.ToNewUInt4BytesBE(state, 8);
            t3 = MemMap.ToNewUInt4BytesBE(state, 12);

            t1 = BinOps.ROL(t1, 8);
            t2 = BinOps.ROL(t2, 16);
            t3 = BinOps.ROL(t3, 24);

            MemMap.ToBytes1UIntBE(t1, state, 4);
            MemMap.ToBytes1UIntBE(t2, state, 8);
            MemMap.ToBytes1UIntBE(t3, state, 12);
        }

        static void MixColumns(byte* state)
        {
            byte s0,s1,s2,s3,r0,r1,r2,r3;

            for (int i = 0; i < 4; i++)
            {
                s0 = state[i + (4 * 0)];
                s1 = state[i + (4 * 1)];
                s2 = state[i + (4 * 2)];
                s3 = state[i + (4 * 3)];

                r0 = (byte)(GFMul(0x02, s0) ^ GFMul(0x03, s1) ^ s2 ^ s3);
                r1 = (byte)(s0 ^ GFMul(0x02, s1) ^ GFMul(0x03, s2) ^ s3);
                r2 = (byte)(s0 ^ s1 ^ GFMul(0x02, s2) ^ GFMul(0x03, s3));
                r3 = (byte)(GFMul(0x03, s0) ^ s1 ^ s2 ^ GFMul(0x02, s3));

                state[i + (4 * 0)] = r0;
                state[i + (4 * 1)] = r1;
                state[i + (4 * 2)] = r2;
                state[i + (4 * 3)] = r3;
            }
        }

        static byte GFMul(byte a, byte b)
        {
            uint red = 0x0000011b; 
            uint sum = 0x00;
            uint temp = 0x00;

            for (int i = 0; i < 8; i++)
            {
                if ((b & (1 << i)) != 0)
                {
                    temp = a;
                    for (int j = 0; j < i; j++)
                    {
                        temp <<= 1;    

                        if ((temp & 0x0100) != 0)
                        {
                            temp ^= red;
                        }
                    } 
                    sum ^= temp;

                    if ((sum & 0x100) != 0) sum ^= red;
                }
            }

            return (byte)sum;
        }

        static void AddRoundKey(byte* state, uint[] roundKey, int roundNo)
        {
            uint k;

            for (int i = 0; i < 4; i++)
            {
                k = roundKey[i + (roundNo * 4)];
                state[i + ( 0)] ^= (byte)((k >> 24) & 0xFF);
                state[i + ( 4)] ^= (byte)((k >> 16) & 0xFF);
                state[i + ( 8)] ^= (byte)((k >> 08) & 0xFF);
                state[i + (12)] ^= (byte)((k >> 00) & 0xFF);
            }
        }
        
        static void SubBytes(byte* state) 
        {
            for (int i = 0; i < 16; i++) state[i] = sbox[state[i]];
        }

        static void ExpandKey(byte[] key, uint[] w)
        {
            int Nk = key.Length / 4;
            uint temp, expandedLen;

            if (Nk == 4)
            {
                MemMap.ToUInt16BytesBE(key, 0, w, 0);
                expandedLen = (RoundsCount128 + 1) * 4;
            }
            else if (Nk == 6)
            {
                MemMap.ToUInt24BytesBE(key, 0, w, 0); 
                expandedLen = (RoundsCount192 + 1) * 4;
            }
            else
            {
                MemMap.ToUInt32BytesBE(key, 0, w, 0); 
                expandedLen = (RoundsCount256 + 1) * 4;
            }


            for (int i = Nk; i < expandedLen; i++)
            {
               temp = w[i - 1]; 
               
               if (i % Nk == 0) temp = SubWord(BinOps.ROL(temp, 8)) ^ Rcon[(i / Nk) - 1];
               else if (Nk > 6 && i % Nk == 4) temp = SubWord(temp);

               w[i] = w[i - Nk] ^ temp;
            }
        }

        static uint SubWord(uint i)
        {
            uint r = 0;

            r |= ((uint)sbox[(i >> 24) & (0xFF)] << 24);
            r |= ((uint)sbox[(i >> 16) & (0xFF)] << 16);
            r |= ((uint)sbox[(i >> 08) & (0xFF)] << 08);
            r |= ((uint)sbox[(i >> 00) & (0xFF)] << 00);

            return r;
        }

        static int RoundsCount(int keyLengthInBytes)
        {
            if (keyLengthInBytes == 16) return RoundsCount128;
            else if (keyLengthInBytes == 24) return RoundsCount192;
            else return RoundsCount256;
        }
    }
}
