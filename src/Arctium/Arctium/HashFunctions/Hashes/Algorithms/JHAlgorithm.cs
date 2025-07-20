/*
 * Implementation of JH Hash Function (224, 256, 384, 512 output hash length)
 * Original Author: Hongjun Wu
 * 
 * Implementation from document named: 'jh20110116.pdf'
 * Document was taken from NIST competition
 * 
 * Implemented by NeuroXiq (2021)
 * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
 */


using System;
using Arctium.Shared.Helpers;
using System.Runtime.CompilerServices;
using Arctium.Shared.Helpers.Buffers;

namespace Arctium.Cryptography.HashFunctions.Hashes.Algorithms
{
    public static class JHAlgorithm
    {
        private const long InputBlockSizeInBytes = 64;
        private static ulong[] alwaysZero8Ulong = new ulong[8];

        public class JHContext
        {
            public ulong[] H;
            public int HashSizeInBits;
            public ulong HashedBytesCount = 0;

            public JHContext(int hashSize)
            {
                this.HashSizeInBits = hashSize;
                H = new ulong[16];
                HashedBytesCount = 0;
                ulong[] Input = new ulong[8];
            }
        }

        public static unsafe void HashBytes(JHContext context, byte[] buffer, long offset, long length)
        {
            ulong* input = stackalloc ulong[8];

            fixed (byte* bufferp = &buffer[0])
            {
                fixed (ulong* contextHp = &context.H[0])
                {
                    for (long i = offset; i < offset + length; i += (InputBlockSizeInBytes))
                    {
                        MemMap.ToULong64BytesBE(bufferp, i, input, 0);
                        ExecuteCompressionFunction_F8(contextHp, input);
                    }
                }
            }

            context.HashedBytesCount += (ulong)length;
        }

        public static unsafe void HashLastBlock(JHContext jhcontext, byte[] buffer, long offset, long length)
        {
            byte[] lastBlockTemp = new byte[128];
            ulong[] lastTwoBlocks = new ulong[16];

            MemOps.Memset(lastBlockTemp, 0, 128, 0);

            for (int i = 0; i < length; i++) lastBlockTemp[i] = buffer[offset + i];

            lastBlockTemp[length] = 0x80;
            ulong msgLenInBits = (jhcontext.HashedBytesCount + (ulong)length) * 8;
            bool isMsgLenMultiply512 = msgLenInBits % 512 == 0;

            fixed (ulong* lastTwoBlocksp = &lastTwoBlocks[0], context = &jhcontext.H[0])
            {
                if (isMsgLenMultiply512)
                {
                    MemMap.ToBytes1ULongBE(msgLenInBits, lastBlockTemp, 56);
                    MemMap.ToULong128BytesBE(lastBlockTemp, 0, lastTwoBlocks, 0);
                    ExecuteCompressionFunction_F8(context, lastTwoBlocksp);
                }
                else
                {
                    MemMap.ToBytes1ULongBE(msgLenInBits, lastBlockTemp, 120);
                    MemMap.ToULong128BytesBE(lastBlockTemp, 0, lastTwoBlocks, 0);
                    ExecuteCompressionFunction_F8(context, lastTwoBlocksp);
                    Array.Copy(lastTwoBlocks, 8, lastTwoBlocks, 0, 8);
                    ExecuteCompressionFunction_F8(context, lastTwoBlocksp);
                }
            }
        }

        public static void GetHash(JHContext context, byte[] outputBuffer, long outputOffset)
        {
            if (context.HashSizeInBits == 512)
            {
                MemMap.ToBytes8ULongBE(context.H, 8, outputBuffer, outputOffset);
            }
            else if (context.HashSizeInBits == 256)
            {
                MemMap.ToBytes4ULongBE(context.H, 12, outputBuffer, outputOffset);
            }
            else if (context.HashSizeInBits == 384)
            {
                MemMap.ToBytes6ULongBE(context.H, 10, outputBuffer, outputOffset);
            }
            else if (context.HashSizeInBits == 224)
            {
                MemMap.ToBytes3ULongBE(context.H, 13, outputBuffer, outputOffset + 4);
                MemMap.ToBytes1UIntBE((uint)context.H[12], outputBuffer, outputOffset);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static unsafe void ExecuteCompressionFunction_F8(ulong* contextH, ulong* inputa)
        {
            ulong t0, t1;

            for (int i = 0; i < 8; i++) contextH[i] ^= inputa[i];

            ulong* input = contextH;

            for (int i = 0; i < 42; i++)
            {
                int ci = i * 2;
                int ci2 = ci + 1;
                /* Sbitsli */

                // 0, 2, 4, 6
                input[12] = ~input[12]; input[13] = ~input[13];
                input[0] ^= (C[ci, 0] & (~input[8])); input[1] ^= (C[ci, 1] & (~input[9]));
                t0 = C[ci, 0] ^ (input[0] & input[4]); t1 = C[ci ,1] ^ (input[1] & input[5]);
                input[0] ^= (input[8] & input[12]); input[1] ^= (input[9] & input[13]);
                input[12] ^= (~input[4]) & input[8]; input[13] ^= (~input[5]) & input[9];
                input[4] ^= input[0] & input[8]; input[5] ^= input[1] & input[9];
                input[8] ^= input[0] & (~input[12]); input[9] ^= input[1] & (~input[13]);
                input[0] ^= input[4] | input[12]; input[1] ^= input[5] | input[13];
                input[12] ^= input[4] & input[8]; input[13] ^= input[5] & input[9];
                input[4] ^= t0 & input[0]; input[5] ^= t1 & input[1];
                input[8] ^= t0; input[9] ^= t1;
                
                // 1, 3, 5, 6
                input[14] = ~input[14]; input[15] = ~input[15];
                input[2] ^= (C[ci2, 0] & (~input[10])); input[3] ^= (C[ci2, 1] & (~input[11]));
                t0 = C[ci2, 0] ^ (input[2] & input[6]); t1 = C[ci2, 1] ^ (input[3] & input[7]);
                input[2] ^= (input[10] & input[14]); input[3] ^= (input[11] & input[15]);
                input[14] ^= (~input[6]) & input[10]; input[15] ^= (~input[7]) & input[11];
                input[6] ^= input[2] & input[10]; input[7] ^= input[3] & input[11];
                input[10] ^= input[2] & (~input[14]); input[11] ^= input[3] & (~input[15]);
                input[2] ^= input[6] | input[14]; input[3] ^= input[7] | input[15];
                input[14] ^= input[6] & input[10]; input[15] ^= input[7] & input[11];
                input[6] ^= t0 & input[2]; input[7] ^= t1 & input[3];
                input[10] ^= t0; input[11] ^= t1;
                
                // Lbitsli
                input[2] ^= input[4]; input[3] ^= input[5];
                input[6] ^= input[8]; input[7] ^= input[9];
                input[10] ^= input[12] ^ input[0]; input[11] ^= input[13] ^ input[1];
                input[14] ^= input[0]; input[15] ^= input[1];
                input[0] ^= input[6]; input[1] ^= input[7];
                input[4] ^= input[10]; input[5] ^= input[11];
                input[8] ^= input[14] ^ input[2]; input[9] ^= input[15] ^ input[3];
                input[12] ^= input[2]; input[13] ^= input[3];

                //Omega_Swap(&input[2], &input[3], 1 << (i % 7));
                //Omega_Swap(&input[6], &input[7], 1 << (i % 7));
                //Omega_Swap(&input[10], &input[11], 1 << (i % 7));
                //Omega_Swap(&input[14], &input[15], 1 << (i % 7));

                // Omega_Swap3(input, 1 << (i % 7));

                int n = 1 << (i % 7);
                ulong* ip = input;

                if (n == 64)
                {
                    ulong t = ip[2];
                    ip[2] = ip[3];
                    ip[3] = t;

                    t = ip[6];
                    ip[6] = ip[7];
                    ip[7] = t;

                    t = ip[10];
                    ip[10] = ip[11];
                    ip[11] = t;

                    t = ip[14];
                    ip[14] = ip[15];
                    ip[15] = t;
                }
                else if (n == 32)
                {
                    // a1 = (a1 >> 32) | (a1 << 32);
                    // a2 = (a2 >> 32) | (a2 << 32);

                    ip[2] = (ip[2] >> 32) | (ip[2] << 32);
                    ip[3] = (ip[3] >> 32) | (ip[3] << 32);

                    ip[6] = (ip[6] >> 32) | (ip[6] << 32);
                    ip[7] = (ip[7] >> 32) | (ip[7] << 32);

                    ip[10] = (ip[10] >> 32) | (ip[10] << 32);
                    ip[11] = (ip[11] >> 32) | (ip[11] << 32);

                    ip[14] = (ip[14] >> 32) | (ip[14] << 32);
                    ip[15] = (ip[15] >> 32) | (ip[15] << 32);

                }
                else if (n == 16)
                {
                    ip[2] = ((ip[2] & 0xFFFF0000FFFF0000UL) >> 16) | ((ip[2] & 0x0000FFFF0000FFFFUL) << 16);
                    ip[3] = ((ip[3] & 0xFFFF0000FFFF0000UL) >> 16) | ((ip[3] & 0x0000FFFF0000FFFFUL) << 16);

                    ip[6] = ((ip[6] & 0xFFFF0000FFFF0000UL) >> 16) | ((ip[6] & 0x0000FFFF0000FFFFUL) << 16);
                    ip[7] = ((ip[7] & 0xFFFF0000FFFF0000UL) >> 16) | ((ip[7] & 0x0000FFFF0000FFFFUL) << 16);

                    ip[10] = ((ip[10] & 0xFFFF0000FFFF0000UL) >> 16) | ((ip[10] & 0x0000FFFF0000FFFFUL) << 16);
                    ip[11] = ((ip[11] & 0xFFFF0000FFFF0000UL) >> 16) | ((ip[11] & 0x0000FFFF0000FFFFUL) << 16);

                    ip[14] = ((ip[14] & 0xFFFF0000FFFF0000UL) >> 16) | ((ip[14] & 0x0000FFFF0000FFFFUL) << 16);
                    ip[15] = ((ip[15] & 0xFFFF0000FFFF0000UL) >> 16) | ((ip[15] & 0x0000FFFF0000FFFFUL) << 16);
                }
                else if (n == 8)
                {
                    ip[2] = ((ip[2] & 0xFF00FF00FF00FF00UL) >> 8) | ((ip[2] & 0x00FF00FF00FF00FFUL) << 8);
                    ip[3] = ((ip[3] & 0xFF00FF00FF00FF00UL) >> 8) | ((ip[3] & 0x00FF00FF00FF00FFUL) << 8);

                    ip[6] = ((ip[6] & 0xFF00FF00FF00FF00UL) >> 8) | ((ip[6] & 0x00FF00FF00FF00FFUL) << 8);
                    ip[7] = ((ip[7] & 0xFF00FF00FF00FF00UL) >> 8) | ((ip[7] & 0x00FF00FF00FF00FFUL) << 8);

                    ip[10] = ((ip[10] & 0xFF00FF00FF00FF00UL) >> 8) | ((ip[10] & 0x00FF00FF00FF00FFUL) << 8);
                    ip[11] = ((ip[11] & 0xFF00FF00FF00FF00UL) >> 8) | ((ip[11] & 0x00FF00FF00FF00FFUL) << 8);

                    ip[14] = ((ip[14] & 0xFF00FF00FF00FF00UL) >> 8) | ((ip[14] & 0x00FF00FF00FF00FFUL) << 8);
                    ip[15] = ((ip[15] & 0xFF00FF00FF00FF00UL) >> 8) | ((ip[15] & 0x00FF00FF00FF00FFUL) << 8);
                }
                else if (n == 4)
                {
                    ip[2] = ((ip[2] & 0xF0F0F0F0F0F0F0F0UL) >> 4) | ((ip[2] & 0x0F0F0F0F0F0F0F0FUL) << 4);
                    ip[3] = ((ip[3] & 0xF0F0F0F0F0F0F0F0UL) >> 4) | ((ip[3] & 0x0F0F0F0F0F0F0F0FUL) << 4);

                    ip[6] = ((ip[6] & 0xF0F0F0F0F0F0F0F0UL) >> 4) | ((ip[6] & 0x0F0F0F0F0F0F0F0FUL) << 4);
                    ip[7] = ((ip[7] & 0xF0F0F0F0F0F0F0F0UL) >> 4) | ((ip[7] & 0x0F0F0F0F0F0F0F0FUL) << 4);

                    ip[10] = ((ip[10] & 0xF0F0F0F0F0F0F0F0UL) >> 4) | ((ip[10] & 0x0F0F0F0F0F0F0F0FUL) << 4);
                    ip[11] = ((ip[11] & 0xF0F0F0F0F0F0F0F0UL) >> 4) | ((ip[11] & 0x0F0F0F0F0F0F0F0FUL) << 4);

                    ip[14] = ((ip[14] & 0xF0F0F0F0F0F0F0F0UL) >> 4) | ((ip[14] & 0x0F0F0F0F0F0F0F0FUL) << 4);
                    ip[15] = ((ip[15] & 0xF0F0F0F0F0F0F0F0UL) >> 4) | ((ip[15] & 0x0F0F0F0F0F0F0F0FUL) << 4);
                }
                else if (n == 2)
                {
                    ip[2] = ((ip[2] & 0xCCCCCCCCCCCCCCCCUL) >> 2) | ((ip[2] & 0x3333333333333333UL) << 2);
                    ip[3] = ((ip[3] & 0xCCCCCCCCCCCCCCCCUL) >> 2) | ((ip[3] & 0x3333333333333333UL) << 2);

                    ip[6] = ((ip[6] & 0xCCCCCCCCCCCCCCCCUL) >> 2) | ((ip[6] & 0x3333333333333333UL) << 2);
                    ip[7] = ((ip[7] & 0xCCCCCCCCCCCCCCCCUL) >> 2) | ((ip[7] & 0x3333333333333333UL) << 2);

                    ip[10] = ((ip[10] & 0xCCCCCCCCCCCCCCCCUL) >> 2) | ((ip[10] & 0x3333333333333333UL) << 2);
                    ip[11] = ((ip[11] & 0xCCCCCCCCCCCCCCCCUL) >> 2) | ((ip[11] & 0x3333333333333333UL) << 2);

                    ip[14] = ((ip[14] & 0xCCCCCCCCCCCCCCCCUL) >> 2) | ((ip[14] & 0x3333333333333333UL) << 2);
                    ip[15] = ((ip[15] & 0xCCCCCCCCCCCCCCCCUL) >> 2) | ((ip[15] & 0x3333333333333333UL) << 2);
                }
                else if (n == 1)
                {
                    ip[2] = ((ip[2] & 0xAAAAAAAAAAAAAAAAUL) >> 1) | ((ip[2] & 0x5555555555555555UL) << 1);
                    ip[3] = ((ip[3] & 0xAAAAAAAAAAAAAAAAUL) >> 1) | ((ip[3] & 0x5555555555555555UL) << 1);

                    ip[6] = ((ip[6] & 0xAAAAAAAAAAAAAAAAUL) >> 1) | ((ip[6] & 0x5555555555555555UL) << 1);
                    ip[7] = ((ip[7] & 0xAAAAAAAAAAAAAAAAUL) >> 1) | ((ip[7] & 0x5555555555555555UL) << 1);

                    ip[10] = ((ip[10] & 0xAAAAAAAAAAAAAAAAUL) >> 1) | ((ip[10] & 0x5555555555555555UL) << 1);
                    ip[11] = ((ip[11] & 0xAAAAAAAAAAAAAAAAUL) >> 1) | ((ip[11] & 0x5555555555555555UL) << 1);

                    ip[14] = ((ip[14] & 0xAAAAAAAAAAAAAAAAUL) >> 1) | ((ip[14] & 0x5555555555555555UL) << 1);
                    ip[15] = ((ip[15] & 0xAAAAAAAAAAAAAAAAUL) >> 1) | ((ip[15] & 0x5555555555555555UL) << 1);
                }
                else throw new Exception();
            }

            for (int i = 0; i < 8; i++) contextH[i + 8] ^= inputa[i];
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        static unsafe void Omega_Swap(ulong* a1p, ulong* a2p, int n)
        {
            ulong a1 = *a1p, a2 = *a2p;

            if(n == 64)
            {
                ulong t = a2;
                a2 = a1;
                a1 = t;
            }
            else if (n == 32)
            {
                a1 = (a1 >> 32) | (a1 << 32);
                a2 = (a2 >> 32) | (a2 << 32);
            } 
            else if (n == 16)
            {
                a1 = ((a1 & 0xFFFF0000FFFF0000UL) >> 16) | ((a1 & 0x0000FFFF0000FFFFUL) << 16);
                a2 = ((a2 & 0xFFFF0000FFFF0000UL) >> 16) | ((a2 & 0x0000FFFF0000FFFFUL) << 16);
            }
            else if (n == 8)
            {
                a1 = ((a1 & 0xFF00FF00FF00FF00UL) >> 8) | ((a1 & 0x00FF00FF00FF00FFUL) << 8);
                a2 = ((a2 & 0xFF00FF00FF00FF00UL) >> 8) | ((a2 & 0x00FF00FF00FF00FFUL) << 8);
            }
            else if (n == 4)
            {
                a1 = ((a1 & 0xF0F0F0F0F0F0F0F0UL) >> 4) | ((a1 & 0x0F0F0F0F0F0F0F0FUL) << 4);
                a2 = ((a2 & 0xF0F0F0F0F0F0F0F0UL) >> 4) | ((a2 & 0x0F0F0F0F0F0F0F0FUL) << 4);
            }
            else if (n == 2)
            {
                a1 = ((a1 & 0xCCCCCCCCCCCCCCCCUL) >> 2) | ((a1 & 0x3333333333333333UL) << 2);
                a2 = ((a2 & 0xCCCCCCCCCCCCCCCCUL) >> 2) | ((a2 & 0x3333333333333333UL) << 2);
            }
            else if (n == 1)
            {
                a1 = ((a1 & 0xAAAAAAAAAAAAAAAAUL) >> 1) | ((a1 & 0x5555555555555555UL) << 1);
                a2 = ((a2 & 0xAAAAAAAAAAAAAAAAUL) >> 1) | ((a2 & 0x5555555555555555UL) << 1);
            }
            else throw new Exception();

            *a1p = a1;
            *a2p = a2;
        }

        public static JHContext Initialize(int hashSize)
        {
            JHContext context = new JHContext(hashSize);

            Reset(context);

            return context;
        }

        public static unsafe void Reset(JHContext context)
        {
            for (int i = 0; i < 16; i++) context.H[i] = 0;

            // Initial Hash Value (H(0))
            context.H[0] = ((ulong)context.HashSizeInBits) << 48;

            fixed (ulong* contextp = &context.H[0], alwaysZero8Ulongp = &alwaysZero8Ulong[0])
            {
                ExecuteCompressionFunction_F8(contextp, alwaysZero8Ulongp);
            }

            context.HashedBytesCount = 0;
        }

        private static readonly ulong[,] C = new ulong[,]
        {
            { 0x72d5dea2df15f867, 0x7b84150ab7231557 },
            { 0x81abd6904d5a87f6, 0x4e9f4fc5c3d12b40 },
            { 0xea983ae05c45fa9c, 0x03c5d29966b2999a },
            { 0x660296b4f2bb538a, 0xb556141a88dba231 },
            { 0x03a35a5c9a190edb, 0x403fb20a87c14410 },
            { 0x1c051980849e951d, 0x6f33ebad5ee7cddc },
            { 0x10ba139202bf6b41, 0xdc786515f7bb27d0 },
            { 0x0a2c813937aa7850, 0x3f1abfd2410091d3 },
            { 0x422d5a0df6cc7e90, 0xdd629f9c92c097ce },
            { 0x185ca70bc72b44ac, 0xd1df65d663c6fc23 },
            { 0x976e6c039ee0b81a, 0x2105457e446ceca8 },
            { 0xeef103bb5d8e61fa, 0xfd9697b294838197 },
            { 0x4a8e8537db03302f, 0x2a678d2dfb9f6a95 },
            { 0x8afe7381f8b8696c, 0x8ac77246c07f4214 },
            { 0xc5f4158fbdc75ec4, 0x75446fa78f11bb80 },
            { 0x52de75b7aee488bc, 0x82b8001e98a6a3f4 },
            { 0x8ef48f33a9a36315, 0xaa5f5624d5b7f989 },
            { 0xb6f1ed207c5ae0fd, 0x36cae95a06422c36 },
            { 0xce2935434efe983d, 0x533af974739a4ba7 },
            { 0xd0f51f596f4e8186, 0x0e9dad81afd85a9f },
            { 0xa7050667ee34626a, 0x8b0b28be6eb91727 },
            { 0x47740726c680103f, 0xe0a07e6fc67e487b },
            { 0x0d550aa54af8a4c0, 0x91e3e79f978ef19e },
            { 0x8676728150608dd4, 0x7e9e5a41f3e5b062 },
            { 0xfc9f1fec4054207a, 0xe3e41a00cef4c984 },
            { 0x4fd794f59dfa95d8, 0x552e7e1124c354a5 },
            { 0x5bdf7228bdfe6e28, 0x78f57fe20fa5c4b2 },
            { 0x05897cefee49d32e, 0x447e9385eb28597f },
            { 0x705f6937b324314a, 0x5e8628f11dd6e465 },
            { 0xc71b770451b920e7, 0x74fe43e823d4878a },
            { 0x7d29e8a3927694f2, 0xddcb7a099b30d9c1 },
            { 0x1d1b30fb5bdc1be0, 0xda24494ff29c82bf },
            { 0xa4e7ba31b470bfff, 0x0d324405def8bc48 },
            { 0x3baefc3253bbd339, 0x459fc3c1e0298ba0 },
            { 0xe5c905fdf7ae090f, 0x947034124290f134 },
            { 0xa271b701e344ed95, 0xe93b8e364f2f984a },
            { 0x88401d63a06cf615, 0x47c1444b8752afff },
            { 0x7ebb4af1e20ac630, 0x4670b6c5cc6e8ce6 },
            { 0xa4d5a456bd4fca00, 0xda9d844bc83e18ae },
            { 0x7357ce453064d1ad, 0xe8a6ce68145c2567 },
            { 0xa3da8cf2cb0ee116, 0x33e906589a94999a },
            { 0x1f60b220c26f847b, 0xd1ceac7fa0d18518 },
            { 0x32595ba18ddd19d3, 0x509a1cc0aaa5b446 },
            { 0x9f3d6367e4046bba, 0xf6ca19ab0b56ee7e },
            { 0x1fb179eaa9282174, 0xe9bdf7353b3651ee },
            { 0x1d57ac5a7550d376, 0x3a46c2fea37d7001 },
            { 0xf735c1af98a4d842, 0x78edec209e6b6779 },
            { 0x41836315ea3adba8, 0xfac33b4d32832c83 },
            { 0xa7403b1f1c2747f3, 0x5940f034b72d769a },
            { 0xe73e4e6cd2214ffd, 0xb8fd8d39dc5759ef },
            { 0x8d9b0c492b49ebda, 0x5ba2d74968f3700d },
            { 0x7d3baed07a8d5584, 0xf5a5e9f0e4f88e65 },
            { 0xa0b8a2f436103b53, 0x0ca8079e753eec5a },
            { 0x9168949256e8884f, 0x5bb05c55f8babc4c },
            { 0xe3bb3b99f387947b, 0x75daf4d6726b1c5d },
            { 0x64aeac28dc34b36d, 0x6c34a550b828db71 },
            { 0xf861e2f2108d512a, 0xe3db643359dd75fc },
            { 0x1cacbcf143ce3fa2, 0x67bbd13c02e843b0 },
            { 0x330a5bca8829a175, 0x7f34194db416535c },
            { 0x923b94c30e794d1e, 0x797475d7b6eeaf3f },
            { 0xeaa8d4f7be1a3921, 0x5cf47e094c232751 },
            { 0x26a32453ba323cd2, 0x44a3174a6da6d5ad },
            { 0xb51d3ea6aff2c908, 0x83593d98916b3c56 },
            { 0x4cf87ca17286604d, 0x46e23ecc086ec7f6 },
            { 0x2f9833b3b1bc765e, 0x2bd666a5efc4e62a },
            { 0x06f4b6e8bec1d436, 0x74ee8215bcef2163 },
            { 0xfdc14e0df453c969, 0xa77d5ac406585826 },
            { 0x7ec1141606e0fa16, 0x7e90af3d28639d3f },
            { 0xd2c9f2e3009bd20c, 0x5faace30b7d40c30 },
            { 0x742a5116f2e03298, 0x0deb30d8e3cef89a },
            { 0x4bc59e7bb5f17992, 0xff51e66e048668d3 },
            { 0x9b234d57e6966731, 0xcce6a6f3170a7505 },
            { 0xb17681d913326cce, 0x3c175284f805a262 },
            { 0xf42bcbb378471547, 0xff46548223936a48 },
            { 0x38df58074e5e6565, 0xf2fc7c89fc86508e },
            { 0x31702e44d00bca86, 0xf04009a23078474e },
            { 0x65a0ee39d1f73883, 0xf75ee937e42c3abd },
            { 0x2197b2260113f86f, 0xa344edd1ef9fdee7 },
            { 0x8ba0df15762592d9, 0x3c85f7f612dc42be },
            { 0xd8a7ec7cab27b07e, 0x538d7ddaaa3ea8de },
            { 0xaa25ce93bd0269d8, 0x5af643fd1a7308f9 },
            { 0xc05fefda174a19a5, 0x974d66334cfd216a },
            { 0x35b49831db411570, 0xea1e0fbbedcd549b },
            { 0x9ad063a151974072, 0xf6759dbf91476fe2 }
        };
    }
}
