using Arctium.Cryptography.CryptoHelpers;
using Arctium.Cryptography.Exceptions;
using System;

namespace Arctium.Cryptography.HashFunctions
{
    static class SHA2_224_256_Shared
    {
        static uint[] ConstantWords = new uint[]
        {
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
            0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
            0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
            0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
            0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
            0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
            0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
            0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
            0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
        };

        /// <summary>
        /// Shared SHA224 & SHA256 function.
        /// Performs main hash computation. All data must be valid, input must be a 512-bit blocks (must be padded before this method call)
        /// </summary>
        /// <param name="inputBuffer">512-bit blocks of data to hash. </param>
        /// <param name="inputOffset">start offset</param>
        /// <param name="inputLength">length to hash</param>
        /// <param name="workingVariables">state variables, contains current hash value</param>
        /// <param name="messageScheduleBuffer">For performance reason, this is a reusable buffer where sheduled message will be stored. 
        /// Alloced only once instead of alloc-per-call. Length must be 64 bytes.
        /// </param>
        internal static void PerformHashComputation(
            byte[] inputBuffer,
            int inputOffset,
            int inputLength,
            uint[] workingVariables,
            uint[] messageScheduleBuffer)
        {
            int blocksCount = inputLength / 64;
            uint[] w = messageScheduleBuffer;
            uint[] k = ConstantWords;

            uint[] vars = new uint[8];

            //for every block
            for (int i = 0; i < blocksCount; i++)
            {
                workingVariables.CopyTo(vars, 0);
                int currentOffset = (i * (64)) + inputOffset;

                PrepareMessageScheduleBuffer(inputBuffer, currentOffset, w);

                //for every 'uint' in scheduled message
                for (int j = 0; j < 64; j++)
                {
                    uint t1 = vars[7] + BitLogic.BSIG1(vars[4]) + BitLogic.CH(vars[4], vars[5], vars[6]) + k[j] + w[j];
                    uint t2 = BitLogic.BSIG0(vars[0]) + BitLogic.MAJ(vars[0], vars[1], vars[2]);

                    vars[7] = vars[6];
                    vars[6] = vars[5];
                    vars[5] = vars[4];
                    vars[4] = vars[3] + t1;
                    vars[3] = vars[2];
                    vars[2] = vars[1];
                    vars[1] = vars[0];
                    vars[0] = t1 + t2;
                }

                for (int j = 0; j < 8; j++)
                {
                    workingVariables[j] += vars[j];
                }
            }
        }

        static void PrepareMessageScheduleBuffer(byte[] inputBuffer, int currentOffset, uint[] outputBuffet)
        {
            uint[] w = outputBuffet;
            for (int i = 0; i < 16; i++)
            {
                w[i] = BinOps.ToUIntBigEndian(inputBuffer, currentOffset + (i * 4));
            }

            for (int i = 16; i < 64; i++)
            {
                w[i] = BitLogic.SSIG1(w[i - 2]) + w[i - 7] + BitLogic.SSIG0(w[i - 15]) + w[i - 16];
            }
        }

        public static byte[] GetPadding(long messageLengthInBytes)
        {
            int paddingLenght = 64 - (int)(messageLengthInBytes % 64);            
            //padding do not fit in last block, need to create next
            if (paddingLenght < 9) paddingLenght += 64;

            byte[] padding = new byte[paddingLenght];

            padding[0] = 0x80;
            long totalBitLength = 8 * messageLengthInBytes;
            BinOps.LongToBigEndianBytes(padding, paddingLenght - 8, totalBitLength);

            return padding;
        }

        internal class BitLogic
        {
            public static uint CH(uint x, uint y, uint z)
            {
                return (x & y) ^ ((~x) & z);
            }

            public static uint MAJ(uint x, uint y, uint z)
            {
                return (x & y) ^ (x & z) ^ (y & z);
            }

            public static uint BSIG0(uint x)
            {
                return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
            }

            public static uint BSIG1(uint x)
            {
                return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
            }

            public static uint SSIG0(uint x)
            {
                return ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3);
            }

            public static uint SSIG1(uint x)
            {
                return ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10);
            }

            public static uint ROTR(uint x, int v)
            {
                return (x >> v) | (x << (32 - v));
            }


        }
    }
}
