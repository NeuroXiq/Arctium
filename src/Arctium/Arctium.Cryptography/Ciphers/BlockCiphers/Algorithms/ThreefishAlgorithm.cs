using System;
using System.Runtime.CompilerServices;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Shared.Helpers.Binary;

namespace Arctium.Cryptography.Ciphers.BlockCiphers.Algorithms
{
    public static class ThreefishAlgorithm
    {

        static int[] Rconst256 = new int[]
        {
            14, 16,
            52, 57,
            23, 40,
            05, 37,
            25, 33,
            46, 12,
            58, 22,
            32, 32
        };
        
        static int[] Rconst512 = new int[]
        {
           46, 36, 19, 37,
           33, 27, 14, 42,
           17, 49, 36, 39,
           44, 09, 54, 56,
           39, 30, 34, 24,
           13, 50, 10, 17,
           25, 29, 39, 43,
           08, 35, 56, 22
        };

        static int[] Rconst1024 = new int[]
        {
           24, 13, 08, 47, 08, 17, 22, 37,
           38, 19, 10, 55, 49, 18, 23, 52,
           33, 04, 51, 13, 34, 41, 59, 17,
           05, 20, 48, 41, 47, 28, 16, 25,
           41, 09, 37, 31, 12, 47, 44, 30,
           16, 34, 56, 51, 04, 53, 42, 41,
           31, 44, 47, 46, 19, 42, 44, 25,
           09, 48, 35, 52, 23, 31, 37, 20
        };

        public struct Context
        {
            public ulong[] Key;
            public ulong[] KnwKey;
            public ulong[] OutputBuffer;
            public ulong[] PermutationBuffer;

            // t0, t1, t2 (t2 only in keyschedule)
            public ulong[] T;

            ///<summary>
            /// Number of words is equal to number of 'ulong's in Key and input block size
            ///</summary>
            public int NumberOfWords;
            public int NumberOfRounds;
        }

        const ulong C240 = 0x1BD11BDAA9FC1A22;
        
        //
        // Public methods
        //
        
        public static void Encrypt1024(byte[] input, long inputOffset, byte[] output, long outputOffset, ulong t0, ulong t1, Context context)
        {
            ulong[] o = context.OutputBuffer;
            ulong[] permutationBuf = context.PermutationBuffer;
            ulong[] knwKey = context.KnwKey;
            ulong mixout0, mixout1;
            int subkeyNo;
            ulong[] t = context.T;
            t[0] = t0;
            t[1] = t1;
            t[2] = t0 ^ t1;

            MemCpy.Copy(context.Key, knwKey);

            knwKey[8] = knwKey[0] ^ knwKey[1] ^ knwKey[2] ^ knwKey[3];
            knwKey[8] ^= knwKey[4] ^ knwKey[5] ^ knwKey[6] ^ knwKey[7];
            knwKey[8] ^= C240;

            MemMap.ToULong64BytesLE(input, inputOffset, o, 0);

            for (int i = 0; i < context.NumberOfRounds; i++)
            {
                if (i % 4 == 0)
                {
                    subkeyNo = i / 4;
                    o[0] += knwKey[(subkeyNo + 0) % 9];
                    o[1] += knwKey[(subkeyNo + 1) % 9];
                    o[2] += knwKey[(subkeyNo + 2) % 9];
                    o[3] += knwKey[(subkeyNo + 3) % 9];
                    o[4] += knwKey[(subkeyNo + 4) % 9];
                    o[5] += knwKey[(subkeyNo + 5) % 9] + t[subkeyNo % 3];
                    o[6] += knwKey[(subkeyNo + 6) % 9] + t[(subkeyNo + 1) % 3];
                    o[7] += knwKey[(subkeyNo + 7) % 9] + (ulong)subkeyNo;
                }

                o[0] = o[0] + o[1];
                o[1] = BinOps.ROL(o[1], Rconst512[(4 * (i % 8)) + 0]) ^ o[0];
                
                o[2] = o[2] + o[3];
                o[3] = BinOps.ROL(o[3], Rconst512[(4 * (i % 8)) + 1]) ^ o[2];
                
                o[4] = o[4] + o[5];
                o[5] = BinOps.ROL(o[5], Rconst512[(4 * (i % 8)) + 2]) ^ o[4];
                
                o[6] = o[6] + o[7];
                o[7] = BinOps.ROL(o[7], Rconst512[(4 * (i % 8)) + 3]) ^ o[6];

                permutationBuf[0] = o[2]; permutationBuf[1] = o[1];
                permutationBuf[2] = o[4]; permutationBuf[3] = o[7];
                permutationBuf[4] = o[6]; permutationBuf[5] = o[5];
                permutationBuf[6] = o[0]; permutationBuf[7] = o[3];

                MemCpy.Copy(permutationBuf, o);
            }

            o[0] += knwKey[(18 + 0) % 9];
            o[1] += knwKey[(18 + 1) % 9];
            o[2] += knwKey[(18 + 2) % 9];
            o[3] += knwKey[(18 + 3) % 9];
            o[4] += knwKey[(18 + 4) % 9];
            o[5] += knwKey[(18 + 5) % 9] + t[18 % 3];
            o[6] += knwKey[(18 + 6) % 9] + t[(18 + 1) % 3];
            o[7] += knwKey[(18 + 7) % 9] + (ulong)18;

            MemMap.ToBytes8ULongLE(o, 0, output, outputOffset);
        }

        public static void Encrypt512(byte[] input, long inputOffset, byte[] output, long outputOffset, ulong t0, ulong t1, Context context)
        {
            ulong[] o = context.OutputBuffer;
            ulong[] permutationBuf = context.PermutationBuffer;
            ulong[] knwKey = context.KnwKey;
            ulong mixout0, mixout1;
            int subkeyNo;
            ulong[] t = context.T;
            t[0] = t0;
            t[1] = t1;
            t[2] = t0 ^ t1;

            MemCpy.Copy(context.Key, knwKey);

            knwKey[8] = knwKey[0] ^ knwKey[1] ^ knwKey[2] ^ knwKey[3];
            knwKey[8] ^= knwKey[4] ^ knwKey[5] ^ knwKey[6] ^ knwKey[7];
            knwKey[8] ^= C240;

            MemMap.ToULong64BytesLE(input, inputOffset, o, 0);

            for (int i = 0; i < context.NumberOfRounds; i++)
            {
                if (i % 4 == 0)
                {
                    subkeyNo = i / 4;
                    o[0] += knwKey[(subkeyNo + 0) % 9];
                    o[1] += knwKey[(subkeyNo + 1) % 9];
                    o[2] += knwKey[(subkeyNo + 2) % 9];
                    o[3] += knwKey[(subkeyNo + 3) % 9];
                    o[4] += knwKey[(subkeyNo + 4) % 9];
                    o[5] += knwKey[(subkeyNo + 5) % 9] + t[subkeyNo % 3];
                    o[6] += knwKey[(subkeyNo + 6) % 9] + t[(subkeyNo + 1) % 3];
                    o[7] += knwKey[(subkeyNo + 7) % 9] + (ulong)subkeyNo;
                }

                o[0] = o[0] + o[1];
                o[1] = BinOps.ROL(o[1], Rconst512[(4 * (i % 8)) + 0]) ^ o[0];
                
                o[2] = o[2] + o[3];
                o[3] = BinOps.ROL(o[3], Rconst512[(4 * (i % 8)) + 1]) ^ o[2];
                
                o[4] = o[4] + o[5];
                o[5] = BinOps.ROL(o[5], Rconst512[(4 * (i % 8)) + 2]) ^ o[4];
                
                o[6] = o[6] + o[7];
                o[7] = BinOps.ROL(o[7], Rconst512[(4 * (i % 8)) + 3]) ^ o[6];

                permutationBuf[0] = o[2]; permutationBuf[1] = o[1];
                permutationBuf[2] = o[4]; permutationBuf[3] = o[7];
                permutationBuf[4] = o[6]; permutationBuf[5] = o[5];
                permutationBuf[6] = o[0]; permutationBuf[7] = o[3];

                MemCpy.Copy(permutationBuf, o);
            }

            o[0] += knwKey[(18 + 0) % 9];
            o[1] += knwKey[(18 + 1) % 9];
            o[2] += knwKey[(18 + 2) % 9];
            o[3] += knwKey[(18 + 3) % 9];
            o[4] += knwKey[(18 + 4) % 9];
            o[5] += knwKey[(18 + 5) % 9] + t[18 % 3];
            o[6] += knwKey[(18 + 6) % 9] + t[(18 + 1) % 3];
            o[7] += knwKey[(18 + 7) % 9] + (ulong)18;

            MemMap.ToBytes8ULongLE(o, 0, output, outputOffset);
        }

        public static void Decrypt512(byte[] input, long inputOffset, byte[] output, long outputOffset, ulong t0, ulong t1, Context context)
        {
            ulong[] o = context.OutputBuffer;
            ulong[] permutationBuf = context.PermutationBuffer;
            ulong[] knwKey = context.KnwKey;
            ulong mixout0, mixout1;
            int subkeyNo;
            ulong[] t = context.T;
            t[0] = t0;
            t[1] = t1;
            t[2] = t0 ^ t1;

            MemCpy.Copy(context.Key, knwKey);

            knwKey[8] = knwKey[0] ^ knwKey[1] ^ knwKey[2] ^ knwKey[3];
            knwKey[8] ^= knwKey[4] ^ knwKey[5] ^ knwKey[6] ^ knwKey[7];
            knwKey[8] ^= C240;

            MemMap.ToULong64BytesLE(input, inputOffset, o, 0);

            o[0] -= knwKey[(18 + 0) % 9];
            o[1] -= knwKey[(18 + 1) % 9];
            o[2] -= knwKey[(18 + 2) % 9];
            o[3] -= knwKey[(18 + 3) % 9];
            o[4] -= knwKey[(18 + 4) % 9];
            o[5] -= knwKey[(18 + 5) % 9] + t[18 % 3];
            o[6] -= knwKey[(18 + 6) % 9] + t[(18 + 1) % 3];
            o[7] -= knwKey[(18 + 7) % 9] + (ulong)18;

            for (int i = 71; i >= 0; i--)
            {
                permutationBuf[2] = o[0]; permutationBuf[1] = o[1];
                permutationBuf[4] = o[2]; permutationBuf[7] = o[3];
                permutationBuf[6] = o[4]; permutationBuf[5] = o[5];
                permutationBuf[0] = o[6]; permutationBuf[3] = o[7];

                MemCpy.Copy(permutationBuf, o);

                o[1] = BinOps.ROR(o[1] ^ o[0], Rconst512[(4 * (i % 8)) + 0]);
                o[0] = o[0] - o[1];

                o[3] = BinOps.ROR(o[2] ^ o[3], Rconst512[(4 * (i % 8)) + 1]);
                o[2] = o[2] - o[3];
                
                o[5] = BinOps.ROR(o[5] ^ o[4], Rconst512[(4 * (i % 8)) + 2]);
                o[4] = o[4] - o[5];
                
                o[7] = BinOps.ROR(o[7] ^ o[6], Rconst512[(4 * (i % 8)) + 3]);
                o[6] = o[6] - o[7];

                if (i % 4 == 0)
                {
                    subkeyNo = i / 4;
                    o[0] -= knwKey[(subkeyNo + 0) % 9];
                    o[1] -= knwKey[(subkeyNo + 1) % 9];
                    o[2] -= knwKey[(subkeyNo + 2) % 9];
                    o[3] -= knwKey[(subkeyNo + 3) % 9];
                    o[4] -= knwKey[(subkeyNo + 4) % 9];
                    o[5] -= knwKey[(subkeyNo + 5) % 9] + t[subkeyNo % 3];
                    o[6] -= knwKey[(subkeyNo + 6) % 9] + t[(subkeyNo + 1) % 3];
                    o[7] -= knwKey[(subkeyNo + 7) % 9] + (ulong)subkeyNo;
                }
            }

            MemMap.ToBytes8ULongLE(o, 0, output, outputOffset);
        }

        ///<summary>
        /// t0, t1 are tweak params
        ///</summary>
        public static void Encrypt256(byte[] input, long inputOffset, byte[] output, long outputOffset, ulong t0, ulong t1, Context context)
        {
            ulong[] outputBuffer = context.OutputBuffer;
            ulong[] permutation = context.PermutationBuffer;
            ulong mixout0, mixout1;
            int subkeyNo;

            ulong[] t = context.T;
            t[0] = t0;
            t[1] = t1;
            t[2] = t0 ^ t1;

            ulong[] knwKey = context.KnwKey;
            knwKey[0] = context.Key[0];
            knwKey[1] = context.Key[1];
            knwKey[2] = context.Key[2];
            knwKey[3] = context.Key[3];
            knwKey[4] = C240 ^ context.Key[0] ^ context.Key[1] ^ context.Key[2] ^ context.Key[3];

            MemMap.ToULong32BytesLE(input, inputOffset, outputBuffer, 0);
            
            for (int i = 0; i < context.NumberOfRounds; i++)
            {
                if (i % 4 == 0)
                {
                   subkeyNo = i / 4;

                   outputBuffer[0] += knwKey[(subkeyNo + 0) % 5];
                   outputBuffer[1] += knwKey[(subkeyNo + 1) % 5] + t[subkeyNo % 3];
                   outputBuffer[2] += knwKey[(subkeyNo + 2) % 5] + t[(subkeyNo + 1) % 3];
                   outputBuffer[3] += knwKey[(subkeyNo + 3) % 5] + (ulong)subkeyNo;
                }

                Mix256(outputBuffer[0], outputBuffer[1], i, 0, out mixout0, out mixout1);
                outputBuffer[0] = mixout0;
                outputBuffer[1] = mixout1;

                Mix256(outputBuffer[2], outputBuffer[3], i, 1, out mixout0, out mixout1);
                outputBuffer[2] = mixout0;
                outputBuffer[3] = mixout1;

                permutation[0] = outputBuffer[0];
                permutation[1] = outputBuffer[3];
                permutation[2] = outputBuffer[2];
                permutation[3] = outputBuffer[1];

                MemCpy.Copy(permutation, outputBuffer);
            }

            outputBuffer[0] += knwKey[3];
            outputBuffer[1] += knwKey[4] + t[0];
            outputBuffer[2] += knwKey[0] + t[1];
            outputBuffer[3] += knwKey[1] + (ulong)18;
 
            MemMap.ToBytes4ULongLE(outputBuffer, 0, output, outputOffset);
        }

        public static void Decrypt256(byte[] input, long inputOffset, byte[] output, long outputOffset, ulong t0, ulong t1, Context context)
        {
            ulong[] outputBuffer = context.OutputBuffer;
            ulong[] permutation = context.PermutationBuffer;
            ulong mixout0, mixout1;
            int subkeyNo;

            ulong[] t = context.T;
            t[0] = t0;
            t[1] = t1;
            t[2] = t0 ^ t1;

            ulong[] knwKey = context.KnwKey;
            knwKey[0] = context.Key[0];
            knwKey[1] = context.Key[1];
            knwKey[2] = context.Key[2];
            knwKey[3] = context.Key[3];
            knwKey[4] = C240 ^ context.Key[0] ^ context.Key[1] ^ context.Key[2] ^ context.Key[3];

            MemMap.ToULong32BytesLE(input, inputOffset, outputBuffer, 0);

            outputBuffer[0] -= knwKey[3];
            outputBuffer[1] -= knwKey[4] + t[0];
            outputBuffer[2] -= knwKey[0] + t[1];
            outputBuffer[3] -= knwKey[1] + (ulong)18;

            for (int i = 71; i >= 0; i--)
            {
                permutation[0] = outputBuffer[0];
                permutation[1] = outputBuffer[3];
                permutation[2] = outputBuffer[2];
                permutation[3] = outputBuffer[1];

                MemCpy.Copy(permutation, outputBuffer);

                Mix256Decrypt(outputBuffer[0], outputBuffer[1], i, 0, out mixout0, out mixout1);
                outputBuffer[0] = mixout0;
                outputBuffer[1] = mixout1;

                Mix256Decrypt(outputBuffer[2], outputBuffer[3], i, 1, out mixout0, out mixout1);
                outputBuffer[2] = mixout0;
                outputBuffer[3] = mixout1;


                if (i % 4 == 0)
                {
                   subkeyNo = i / 4;

                   outputBuffer[0] -= knwKey[(subkeyNo + 0) % 5];
                   outputBuffer[1] -= knwKey[(subkeyNo + 1) % 5] + t[subkeyNo % 3];
                   outputBuffer[2] -= knwKey[(subkeyNo + 2) % 5] + t[(subkeyNo + 1) % 3];
                   outputBuffer[3] -= knwKey[(subkeyNo + 3) % 5] + (ulong)subkeyNo;
                }

            }
             
            MemMap.ToBytes4ULongLE(outputBuffer, 0, output, outputOffset);
        }

        public static Context Initialise(byte[] key)
        {
            Context context = new Context();

            int blockSize = key.Length * 8;

            context.NumberOfWords = blockSize / 64; 
            context.NumberOfRounds = 72;

            if (blockSize == 1024)
            {
                context.NumberOfRounds = 80;
            }

            context.OutputBuffer = new ulong[context.NumberOfWords];
            context.PermutationBuffer = new ulong[context.NumberOfWords];
            context.Key = new ulong[context.NumberOfWords];
            context.KnwKey = new ulong[context.NumberOfWords + 1];
            context.T = new ulong[3];

            MemMap.ToULongNBytesLE(key, 0, context.Key, 0, context.NumberOfWords);
            
            return context;
        }

        //
        // Private methods
        //
        
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        static void Mix256Decrypt(ulong y0, ulong y1, int roundNo, int j, out ulong x0, out ulong x1)
        {
            x1 = BinOps.ROR(y1 ^ y0, Rconst256[2 * (roundNo % 8) + j]);
            x0 = y0 - x1;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        static void Mix256(ulong x0, ulong x1, int roundNo, int j, out ulong y0, out ulong y1)
        {
            y0 = (x0 + x1);
            y1 = (BinOps.ROL(x1, Rconst256[(2 * (roundNo % 8)) + j])) ^ y0;
        }


        static void KeySchedule(Context context, ulong t0, ulong t1)
        {
            // Compute K_Wn
            // just hold this somewhere, more convenient than varbiale
            //int currentSubkey = 0;
            //int subkeysCount = context.KeySchedule.Length / context.NumberOfWords;
            //context.T[2] = context.T[0] ^ context.T[1];
            //MemCpy.Copy(context.Key, context.KnwKey);
            //context.KnwKey[context.NumberOfWords] = C240;
            //
            //for (int i = 0; i < context.Key.Length; i++)
            //{
            //    context.KnwKey[context.KnwKey.Length - 1] ^= context.Key[i];
            //}

            //for (int i = 0; i < subkeysCount; i++)
            //{
            //    currentSubkey = context.NumberOfWords * i;

            //    for (int j = 0; j < context.NumberOfWords; j++)
            //    {
            //        context.KeySchedule[currentSubkey + j] = context.KnwKey[(i + j) % (context.NumberOfWords + 1)];
            //    }

            //    context.KeySchedule[currentSubkey + context.NumberOfWords - 3] += context.T[i % 3]; 
            //    context.KeySchedule[currentSubkey + context.NumberOfWords - 2] += context.T[(i + 1) % 3]; 
            //    context.KeySchedule[currentSubkey + context.NumberOfWords - 1] += (ulong)i; 
            //}
       }
    }
}
