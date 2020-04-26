using Arctium.Shared.Helpers.Binary;
using Arctium.Shared.Helpers.Buffers;
using System.Runtime.CompilerServices;
using static Arctium.Shared.Helpers.Binary.BinOps;

namespace Arctium.Cryptography.Ciphers.BlockCiphers.EncryptionAlgorithms
{
    /// <summary>
    /// Represents enctyption algorithms for the Twofish cipher.
    /// This is unsafe class, never throws managed exceptions, input data MUST be valid
    /// </summary>
    public static unsafe class TwofishEncryption
    {

        /*
         * Cipher constants
         */

        static byte[] RC = new byte[32] {
            0x01,   0xA4,   0x55,   0x87,   0x5A,   0x58,   0xDB,   0x9E,
            0xA4,   0x56,   0x82,   0xF3,   0x1E,   0xC6,   0x68,   0xE5,
            0x02,   0xA1,   0xFC,   0xC1,   0x47,   0xAE,   0x3D,   0x19,
            0xA4,   0x55,   0x87,   0x5A,   0x58,   0xDB,   0x9E,   0x03
        };

        static byte[] MDS = new byte[] {
            0x01, 0xEF, 0x5B, 0x5B,
            0x5B, 0xEF, 0xEF, 0x01,
            0xEF, 0x5B, 0x01, 0xEF,
            0xEF, 0x01, 0xEF, 0x5B
        };

        static byte[] q0t0 = new byte[] { 0x8, 0x1, 0x7, 0xD, 0x6, 0xF, 0x3, 0x2, 0x0, 0xB, 0x5, 0x9, 0xE, 0xC, 0xA, 0x4 };
        static byte[] q0t1 = new byte[] { 0xE, 0xC, 0xB, 0x8, 0x1, 0x2, 0x3, 0x5, 0xF, 0x4, 0xA, 0x6, 0x7, 0x0, 0x9, 0xD };
        static byte[] q0t2 = new byte[] { 0xB, 0xA, 0x5, 0xE, 0x6, 0xD, 0x9, 0x0, 0xC, 0x8, 0xF, 0x3, 0x2, 0x4, 0x7, 0x1 };
        static byte[] q0t3 = new byte[] { 0xD, 0x7, 0xF, 0x4, 0x1, 0x2, 0x6, 0xE, 0x9, 0xB, 0x3, 0x0, 0x8, 0x5, 0xC, 0xA };

        static byte[] q1t0 = new byte[] { 0x2, 0x8, 0xB, 0xD, 0xF, 0x7, 0x6, 0xE, 0x3, 0x1, 0x9, 0x4, 0x0, 0xA, 0xC, 0x5 };
        static byte[] q1t1 = new byte[] { 0x1, 0xE, 0x2, 0xB, 0x4, 0xC, 0x3, 0x7, 0x6, 0xD, 0xA, 0x5, 0xF, 0x9, 0x0, 0x8 };
        static byte[] q1t2 = new byte[] { 0x4, 0xC, 0x7, 0x5, 0x1, 0x6, 0x9, 0xA, 0x0, 0xE, 0xD, 0x8, 0x2, 0xB, 0x3, 0xF };
        static byte[] q1t3 = new byte[] { 0xB, 0x9, 0x5, 0x1, 0xC, 0x3, 0xD, 0xE, 0x6, 0x4, 0x7, 0xF, 0x2, 0x0, 0x8, 0xA };

        const byte Mod16 = 0x0F;

        public struct EncryptParms
        {
            public byte* Input;
            public byte* Output;
            public uint* ExpandedKey;

            /// <summary>
            /// Third key vector
            /// </summary>
            public uint* SKeyVector;
            public int KeyLength;
        }

        public static void EncryptBlock(EncryptParms parms)
        {
            byte* input = (parms).Input;
            byte* output = (parms).Output;
            uint* expandedKey = (parms).ExpandedKey;
            uint* skeyvector = (parms).SKeyVector;
            int keyQwordsCount = parms.KeyLength / 64;


            uint* p = stackalloc uint[4];

            p[0] = BinConverter.ToUIntLE(&input[0]);
            p[1] = BinConverter.ToUIntLE(&input[4]);
            p[2] = BinConverter.ToUIntLE(&input[8]);
            p[3] = BinConverter.ToUIntLE(&input[12]);

            /* whitening */
            p[0] ^= expandedKey[0];
            p[1] ^= expandedKey[1];
            p[2] ^= expandedKey[2];
            p[3] ^= expandedKey[3];

            for (int round = 0; round < 16; round++)
            {
                /* F function */
                uint t0 = h(p[0], skeyvector, keyQwordsCount);
                uint t1 = h(ROL(p[1], 8), skeyvector, keyQwordsCount);
                uint f0 = t0 + t1 + expandedKey[(2 * round) + 8];
                uint f1 = t0 + (2 * t1) + expandedKey[(2 * round) + 9];
                
                /* F function end */

                uint next0 = ROR(p[2] ^ f0, 1);
                uint next1 = ROL(p[3], 1) ^ f1;
                
                p[2] = p[0];
                p[3] = p[1];
                p[0] = next0;
                p[1] = next1;
                
            }


            /* output whitening */

            // reverse order of last swap
            uint p0Copy = p[0];
            uint p1Copy = p[1];

            p[0] = p[2];
            p[1] = p[3];
            p[2] = p0Copy;
            p[3] = p1Copy;

            p[0] ^= expandedKey[4];
            p[1] ^= expandedKey[5];
            p[2] ^= expandedKey[6];
            p[3] ^= expandedKey[7];

            MemMap.ToBytes4UIntLE(p, output);
        }



        //
        // Strict
        //

        public static void KeySchedule(byte* inputKey, uint* outExpandedKey, uint* outKeyVector, int keyLength)
        {
            int keyQwordCount = keyLength / 64;
            // key vectors

            uint* me = stackalloc uint[keyQwordCount];
            uint* mo = stackalloc uint[keyQwordCount];
            uint* thirdKeyVector = stackalloc uint[keyQwordCount];

            me[0] = BinConverter.ToUIntLE(inputKey + 0);
            mo[0] = BinConverter.ToUIntLE(inputKey + 4);
            me[1] = BinConverter.ToUIntLE(inputKey + 8);
            mo[1] = BinConverter.ToUIntLE(inputKey + 12);

            if (keyQwordCount > 2)
            {
                me[2] = BinConverter.ToUIntLE(inputKey + 16);
                mo[2] = BinConverter.ToUIntLE(inputKey + 20);
            }
            if (keyQwordCount > 3)
            {
                me[3] = BinConverter.ToUIntLE(inputKey + 24);
                mo[3] = BinConverter.ToUIntLE(inputKey + 28);
            }

            ComputeThirdKeyVector(inputKey, thirdKeyVector, keyQwordCount);

            // 3 key vectors generated

            ComputeExpandedKey(me, mo, outExpandedKey, keyQwordCount);
            //Dbg.HexDump(outExpandedKey, 40);
            for (int i = 0; i < keyQwordCount; i++)
            {
                outKeyVector[i] = thirdKeyVector[i];
            }
        }


        public static void ComputeThirdKeyVector(byte* key, uint* outs, int keyQwordCount)
        {
            // key is interpreted as 8 byte vector
            /* [RS matrix]
             * 
             * 01   A4   55   87   5A   58   DB   9E 
             * A4   56   82   F3   1E   C6   68   E5
             * 02   A1   FC   C1   47   AE   3D   19
             * A4   55   87   5A   58   DB   9E   03
             */

            byte irreducible = (1 << 6) + (1 << 3) + (1 << 2) + 1; /* + (1 << 8) */


            for (int i = 0; i < keyQwordCount; i++)
            {
                uint multiplied = 0;
                for (int y = 0; y < 4; y++)
                {
                    byte result = 0;
                    for (int j = 0; j < 8; j++)
                    {
                        result ^= GF2Mul(RC[(y * 8) + j], key[j + (i * 8)], irreducible); // 8 vs 16 ????
                    }

                    // multiplied |= ((uint)result << (24 - (y * 8)));
                    multiplied |= (uint)(result << (y * 8));
                }

                outs[keyQwordCount - 1 - i] = multiplied;
            }

            //multiplied = 0;
            //for (int y = 0; y < 4; y++)
            //{
            //    byte result = 0;
            //    for (int j = 0; j < 8; j++)
            //    {
            //        byte a = RC[(y * 8) + j];
            //        byte b = key[j + 16];
            //        result ^= GF2Mul(a, b, irreducible);
            //    }

            //    multiplied |= ((uint)result << (24 - (y * 8)));
            //}

            //outs[0] = multiplied;
        }

        static void ComputeExpandedKey(uint* me, uint* mo, uint* outk, int keyDwordCount)
        {
            uint r = (1 << 24) + (1 << 16) + (1 << 8) + (1);
            uint a = 0;
            uint b = 0;

            for (uint i = 0; i < 20; i++)
            {
                a = h((2 * i) * r, me, keyDwordCount);
                b = ROL(h(((2 * i) + 1) * r, mo, keyDwordCount), 8);
                outk[2 * i] = (a + b);
                outk[(2 * i) + 1] = (ROL(a + (2 * b), 9));
            }
        }

        public static uint h(uint x, uint* lArray, int lArrayLength)
        {
            byte* l = stackalloc byte[(int)lArrayLength * 4];

            for (int i = 0; i < lArrayLength; i++)
            {
                byte* toBytesOffset = l + (4 * i);
                BinConverter.ToBytesLE(lArray[i], toBytesOffset);
            }

            byte y0 = (byte)(x >> 0);
            byte y1 = (byte)(x >> 8);
            byte y2 = (byte)(x >> 16);
            byte y3 = (byte)(x >> 24);

            if (lArrayLength == 4)
            {
                y0 = (byte)(q1(y0) ^ l[(3 * 4) + 0]);
                y1 = (byte)(q0(y1) ^ l[(3 * 4) + 1]);
                y2 = (byte)(q0(y2) ^ l[(3 * 4) + 2]);
                y3 = (byte)(q1(y3) ^ l[(3 * 4) + 3]);
            }
            if (lArrayLength >= 3)
            {
                y0 = (byte)(q1(y0) ^ l[(2 * 4) + 0]);
                y1 = (byte)(q1(y1) ^ l[(2 * 4) + 1]);
                y2 = (byte)(q0(y2) ^ l[(2 * 4) + 2]);
                y3 = (byte)(q0(y3) ^ l[(2 * 4) + 3]);
            }

            y0 = (byte)q1(q0(q0(y0) ^ l[(1 * 4) + 0]) ^ l[(1 * 0) + 0]);
            y1 = (byte)q0(q0(q1(y1) ^ l[(1 * 4) + 1]) ^ l[(1 * 0) + 1]);
            y2 = (byte)q1(q1(q0(y2) ^ l[(1 * 4) + 2]) ^ l[(1 * 0) + 2]);
            y3 = (byte)q0(q1(q1(y3) ^ l[(1 * 4) + 3]) ^ l[(1 * 0) + 3]);

            uint result = MultiplyByMDS(y0, y1, y2, y3);

            return result;
        }

        static uint MultiplyByMDS(byte y0, byte y1, byte y2, byte y3)
        {

            byte primitive = (1 << 6) + (1 << 5) + (1 << 3) + 1;

            byte z0 = (byte)(
                    GF2Mul(y0, MDS[0], primitive) ^
                    GF2Mul(y1, MDS[1], primitive) ^
                    GF2Mul(y2, MDS[2], primitive) ^
                    GF2Mul(y3, MDS[3], primitive));

            byte z1 = (byte)(
                    GF2Mul(y0, MDS[4], primitive) ^
                    GF2Mul(y1, MDS[5], primitive) ^
                    GF2Mul(y2, MDS[6], primitive) ^
                    GF2Mul(y3, MDS[7], primitive));

            byte z2 = (byte)(
                    GF2Mul(y0, MDS[8], primitive) ^
                    GF2Mul(y1, MDS[9], primitive) ^
                    GF2Mul(y2, MDS[10], primitive) ^
                    GF2Mul(y3, MDS[11], primitive));

            byte z3 = (byte)(
                    GF2Mul(y0, MDS[12], primitive) ^
                    GF2Mul(y1, MDS[13], primitive) ^
                    GF2Mul(y2, MDS[14], primitive) ^
                    GF2Mul(y3, MDS[15], primitive));

            return (uint)((z0) + (z1 << 8) + (z2 << 16) + (z3 << 24));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        static byte GF2Mul(byte value1, byte value2, byte irreducible)
        {
            byte result = 0;
            int carry = 0;


            for (int i = 0; i < 8 && value1 > 0; i++)
            {
                carry = value2 & 0x80;
                if ((value1 & 1) > 0) result ^= value2;
                value1 >>= 1;
                value2 <<= 1;
                if (carry > 0) value2 ^= irreducible;
            }

            return result;
        }

        static uint q0(uint x)
        {
            uint a0 = (byte)(x >> 4);
            uint b0 = (byte)(x & 0x0F);

            uint a1 = a0 ^ b0;
            uint b1 = a0 ^ ROR4(b0, 1) ^ ((8 * a0) & Mod16);

            uint a2 = q0t0[a1];
            uint b2 = q0t1[b1];

            uint a3 = a2 ^ b2;
            uint b3 = a2 ^ ROR4(b2, 1) ^ ((8 * a2) & Mod16);

            uint a4 = q0t2[a3];
            uint b4 = q0t3[b3];

            return (byte)((16 * b4) + a4);
        }

        static uint q1(uint x)
        {
            uint a0 = (byte)(x >> 4);
            uint b0 = (byte)(x & 0x0F);

            uint a1 = a0 ^ b0;
            uint b1 = a0 ^ ROR4(b0, 1) ^ ((8 * a0) & Mod16);

            uint a2 = q1t0[a1];
            uint b2 = q1t1[b1];

            uint a3 = a2 ^ b2;
            uint b3 = a2 ^ ROR4(b2, 1) ^ ((8 * a2) & Mod16);

            uint a4 = q1t2[a3];
            uint b4 = q1t3[b3];

            return (byte)((16 * b4) + a4);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        static uint ROL(uint x, int r)
        {
            return (x << r) | (x >> (32 - r));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        static uint ROR4(uint v, int r)
        {
            return ((v >> r) | (v << (4 - r))) & 0x0F;
        }


        //
        // Generic DEPRECATED
        //

        /// <summary>
        /// 
        /// </summary>
        /// <param name="inputKey"></param>
        /// <param name="keyLength">Length of the key in bits</param>
        /// <param name="outExpandedKey"></param>
        /// <param name="outSBoxes"></param>
        //public static void KeySchedule(byte[] inputKey, int keyLength, uint[] outExpandedKey, uint[] sKeyVector)
        //{
        //    int k = keyLength / 64;
        //    uint wordsCount = (uint)keyLength / 32;

        //    // key vectors

        //    uint* me = stackalloc uint[k];
        //    uint* mo = stackalloc uint[k];
        //    uint* thirdKeyVector = stackalloc uint[k];

        //    for (int i = 0; i < k; i++)
        //    {
        //        me[i] = BinConverter.ToUIntLE(inputKey, i * 8);
        //        mo[i] = BinConverter.ToUIntLE(inputKey, (i * 8) + 4);
        //    }

        //    ComputeThirdKeyVector(inputKey, k * 2, thirdKeyVector);

        //    // 3 key vectors generated

        //    ComputeExpandedKey(me, mo, wordsCount, outExpandedKey);

        //    MemCpy.Copy(thirdKeyVector, sKeyVector, 0, k);
        //}



        //public static void ComputeThirdKeyVector(byte[] key, int keyLengthInWords, uint* outs)
        //{
        //    // key is interpreted as 8 byte vector
        //    /* [RS matrix]
        //     * 
        //     * 01   A4   55   87   5A   58   DB   9E 
        //     * A4   56   82   F3   1E   C6   68   E5
        //     * 02   A1   FC   C1   47   AE   3D   19
        //     * A4   55   87   5A   58   DB   9E   03
        //     */

        //    int writeOut = (keyLengthInWords - 1) * 8;
        //    byte irreducible = (1 << 6) + (1 << 3) + (1 << 2) + 1; /* + (1 << 8) */

        //    for (int i = 0; i < keyLengthInWords; i++)
        //    {
        //        uint multiplied = 0;
        //        for (int y = 0; y < 4; y++)
        //        {
        //            byte result = 0;
        //            for (int j = 0; j < 8; j++)
        //            {
        //                byte a = RC[(y * 8) + j];
        //                byte b = key[j];
        //                result ^= GF2Mul(a, b, irreducible);
        //            }

        //            multiplied |= ((uint)result << (24 - (y * 8)));
        //        }

        //        outs[keyLengthInWords - 1 - i] = multiplied;
        //    }
        //}

        

       
    }
}

/*static void ComputeExpandedKey(uint* me, uint* mo, uint keyLengthInWords, uint[] outk)
        {
            uint r = (1 << 24) + (1 << 16) + (1 << 8) + (1);
            uint a = 0;
            uint b = 0;

            for (uint i = 0; i < 20; i++)
            {
                a = h((2 * i) * r, me, keyLengthInWords / 2);
                b = ROL(h(((2 * i) + 1) * r, mo, keyLengthInWords / 2), 8);
                outk[2 * i] = (a + b);
                outk[(2 * i) + 1] = (ROL(a + (2 * b), 9));
            }
        }*/

/*static void KeyDependentSBox128(byte x, uint[] lArray, byte* outputValue)
        {
            int lArrayLength = 2;
            byte* l = stackalloc byte[(int)lArrayLength * 4];

            for (int i = 0; i < lArrayLength; i++)
            {
                byte* toBytesOffset = l + (4 * i);
                BinConverter.ToBytesLE(lArray[i], toBytesOffset);
            }

            byte y0 = (byte)(x >> 0);
            byte y1 = (byte)(x >> 8);
            byte y2 = (byte)(x >> 16);
            byte y3 = (byte)(x >> 24);

            if (lArrayLength == 4)
            {
                y0 = (byte)(q1(y0) ^ l[(3 * 4) + 3]);
                y1 = (byte)(q0(y1) ^ l[(3 * 4) + 2]);
                y2 = (byte)(q0(y2) ^ l[(3 * 4) + 1]);
                y3 = (byte)(q1(y3) ^ l[(3 * 4) + 0]);
            }
            if (lArrayLength >= 3)
            {
                y0 = (byte)(q1(y0) ^ l[(2 * 4) + 3]);
                y1 = (byte)(q1(y1) ^ l[(2 * 4) + 2]);
                y2 = (byte)(q0(y2) ^ l[(2 * 4) + 1]);
                y3 = (byte)(q0(y3) ^ l[(2 * 4) + 0]);
            }

            outputValue[0] = (byte)q1(q0(q0(y0) ^ l[(1 * 4) + 3]) ^ l[(1 * 0) + 3]);
            outputValue[1] = (byte)q0(q0(q1(y1) ^ l[(1 * 4) + 2]) ^ l[(1 * 0) + 2]);
            outputValue[2] = (byte)q1(q1(q0(y2) ^ l[(1 * 4) + 1]) ^ l[(1 * 0) + 1]);
            outputValue[3] = (byte)q0(q1(q1(y3) ^ l[(1 * 4) + 0]) ^ l[(1 * 0) + 0]);
        }*/
