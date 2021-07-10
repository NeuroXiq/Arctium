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

        public enum BlockSize
        {
            Size256,
            Size512,
            Size1024
        };

        public struct EncryptParams
        {
            public ulong T0, T1; 
            public ulong[] Key;
        }
        
        public struct Context
        {
            public ulong[] Key;
            public ulong[] KnwKey;
            public ulong[] KeySchedule;
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
        
        ///<summary>
        /// t0, t1 are tweak params
        ///</summary>
        public static void Encrypt256(byte[] input, long inputOffset, byte[] output, long outputOffset, ulong t0, ulong t1, Context context)
        {
            context.T[0] = t0;
            context.T[1] = t1;
            ulong[] scheduledKey = context.KeySchedule;
            ulong[] outputBuffer = context.OutputBuffer;
            ulong[] permutation = context.PermutationBuffer;
            ulong mixout0, mixout1;

            MemMap.ToULong32BytesLE(input, inputOffset, outputBuffer, 0);
            
            KeySchedule(context, t0, t1);


            for (int i = 0; i < context.NumberOfRounds; i++)
            {
                if (i % 4 == 0)
                {
                    int subkeyOffset = (i / 4) * context.NumberOfWords;
                    
                    for (int j = 0; j < context.NumberOfWords; j++)
                        outputBuffer[j] += scheduledKey[subkeyOffset + j];
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

            outputBuffer[0] += scheduledKey[scheduledKey.Length - 4];
            outputBuffer[1] += scheduledKey[scheduledKey.Length - 3];
            outputBuffer[2] += scheduledKey[scheduledKey.Length - 2];
            outputBuffer[3] += scheduledKey[scheduledKey.Length - 1];

            MemMap.ToBytes4ULongLE(outputBuffer, 0, output, outputOffset);
        }

        public static void Decrypt256(byte[] input, long inputOffset, byte[] output, long outputOffset, ulong t0, ulong t1, Context context)
        {
        
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

            context.OutputBuffer = new ulong[context.NumberOfRounds / 4];
            context.PermutationBuffer = new ulong[context.NumberOfWords];
            context.Key = new ulong[context.NumberOfWords];
            context.KnwKey = new ulong[context.NumberOfWords + 1];
            context.KeySchedule = new ulong[((context.NumberOfRounds / 4) + 1) * context.NumberOfWords];
            context.T = new ulong[3];

            MemMap.ToULongNBytesLE(key, 0, context.Key, 0, context.NumberOfWords);
            
            return context;
        }

        //
        // Private methods
        //
        
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
            int currentSubkey = 0;
            int subkeysCount = context.KeySchedule.Length / context.NumberOfWords;
            context.T[2] = context.T[0] ^ context.T[1];
            MemCpy.Copy(context.Key, context.KnwKey);
            context.KnwKey[context.NumberOfWords] = C240;
            
            for (int i = 0; i < context.Key.Length; i++)
            {
                context.KnwKey[context.KnwKey.Length - 1] ^= context.Key[i];
            }

            for (int i = 0; i < subkeysCount; i++)
            {
                currentSubkey = context.NumberOfWords * i;

                for (int j = 0; j < context.NumberOfWords; j++)
                {
                    context.KeySchedule[currentSubkey + j] = context.KnwKey[(i + j) % (context.NumberOfWords + 1)];
                }

                context.KeySchedule[currentSubkey + context.NumberOfWords - 3] += context.T[i % 3]; 
                context.KeySchedule[currentSubkey + context.NumberOfWords - 2] += context.T[(i + 1) % 3]; 
                context.KeySchedule[currentSubkey + context.NumberOfWords - 1] += (ulong)i; 
            }
       }
    }
}
