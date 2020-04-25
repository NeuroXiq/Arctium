using Arctium.Cryptography.Exceptions;
using Arctium.Shared.Helpers.Binary;
using System;
using System.Runtime.CompilerServices;

/*
 * Several notes at the end
 * 
 */

namespace  Arctium.Cryptography.HashFunctions.Hashes
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
        internal static unsafe void PerformHashComputation(
            byte[] inputBuffer,
            long inputOffset,
            long inputLength,
            uint[] workingVariables,
            uint[] messageScheduleBuffer)
        {
            long blocksCount = inputLength / 64;

            uint* vars = stackalloc uint[8];
            uint* workingVars = stackalloc uint[8];
            uint* w = stackalloc uint[64];

            // clone original variables stored externally 
            // this vars holds results of hashings from previous blocks/calls
            for (int i = 0; i < 8; i++) workingVars[i] = workingVariables[i];

            //for every block

            fixed (uint* k = &ConstantWords[0])
            {
                for (int i = 0; i < blocksCount; i++)
                {
                    //workingVariables.CopyTo(vars, 0);
                    CopyWorkingVariables(workingVars, vars);

                    long currentOffset = (i * (64)) + inputOffset;

                    PrepareMessageScheduleBuffer(inputBuffer, currentOffset, w);

                    //for every 'uint' in scheduled message
                    Hash64ByteBlock(vars, k, w);

                    SumWorkingVariablesAfterHash(vars, workingVars);
                }
            }

            // write back working vars
            for (int i = 0; i < 8; i++) workingVariables[i] = workingVars[i];
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe void Hash64ByteBlock(uint* vars, uint* k, uint* w)
        {
            //
            // First approach was to unwind this loop and 
            // create 64 calls. But loop is faster instead of calling method 64 times directly (not sure why ?)
            //

            for (int i = 0; i < 64; i++)
            {
                ShiftVarsAndAddTValues(vars,
                    vars[7] + BitLogic.BSIG1(vars[4]) + BitLogic.CH(vars[4], vars[5], vars[6]) + k[i] + w[i], BitLogic.BSIG0(vars[0]) + BitLogic.MAJ(vars[0],
                    vars[1], vars[2]));
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe void SumWorkingVariablesAfterHash(uint* src, uint* dst)
        {
            dst[0] += src[0];
            dst[1] += src[1];
            dst[2] += src[2];
            dst[3] += src[3];

            dst[4] += src[4];
            dst[5] += src[5];
            dst[6] += src[6];
            dst[7] += src[7];
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe void ShiftVarsAndAddTValues(uint* vars, uint t1, uint t2)
        {
            vars[7] = vars[6];
            vars[6] = vars[5];
            vars[5] = vars[4];
            vars[4] = vars[3] + t1;

            vars[3] = vars[2];
            vars[2] = vars[1];
            vars[1] = vars[0];
            vars[0] = t1 + t2;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe void CopyWorkingVariables(uint* src, uint* dst)
        {
            dst[0] = src[0];
            dst[1] = src[1];
            dst[2] = src[2];
            dst[3] = src[3];

            dst[4] = src[4];
            dst[5] = src[5];
            dst[6] = src[6];
            dst[7] = src[7];
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        static unsafe void PrepareMessageScheduleBuffer(byte[] inputBuffer, long currentOffset, uint* w)
        {

            w[0] = BinConverter.ToUIntBE(inputBuffer, currentOffset + (0));
            w[1] = BinConverter.ToUIntBE(inputBuffer, currentOffset + (4));
            w[2] = BinConverter.ToUIntBE(inputBuffer, currentOffset + (8));
            w[3] = BinConverter.ToUIntBE(inputBuffer, currentOffset + (12));
            w[4] = BinConverter.ToUIntBE(inputBuffer, currentOffset + (16));
            w[5] = BinConverter.ToUIntBE(inputBuffer, currentOffset + (20));
            w[6] = BinConverter.ToUIntBE(inputBuffer, currentOffset + (24));
            w[7] = BinConverter.ToUIntBE(inputBuffer, currentOffset + (28));
            w[8] = BinConverter.ToUIntBE(inputBuffer, currentOffset + (32));
            w[9] = BinConverter.ToUIntBE(inputBuffer, currentOffset + (36));
            w[10] = BinConverter.ToUIntBE(inputBuffer, currentOffset + (40));
            w[11] = BinConverter.ToUIntBE(inputBuffer, currentOffset + (44));
            w[12] = BinConverter.ToUIntBE(inputBuffer, currentOffset + (48));
            w[13] = BinConverter.ToUIntBE(inputBuffer, currentOffset + (52));
            w[14] = BinConverter.ToUIntBE(inputBuffer, currentOffset + (56));
            w[15] = BinConverter.ToUIntBE(inputBuffer, currentOffset + (60));

            w[16] = BitLogic.SSIG1(w[14]) + w[9] + BitLogic.SSIG0(w[1]) + w[0];
            w[17] = BitLogic.SSIG1(w[15]) + w[10] + BitLogic.SSIG0(w[2]) + w[1];
            w[18] = BitLogic.SSIG1(w[16]) + w[11] + BitLogic.SSIG0(w[3]) + w[2];
            w[19] = BitLogic.SSIG1(w[17]) + w[12] + BitLogic.SSIG0(w[4]) + w[3];
            w[20] = BitLogic.SSIG1(w[18]) + w[13] + BitLogic.SSIG0(w[5]) + w[4];
            w[21] = BitLogic.SSIG1(w[19]) + w[14] + BitLogic.SSIG0(w[6]) + w[5];
            w[22] = BitLogic.SSIG1(w[20]) + w[15] + BitLogic.SSIG0(w[7]) + w[6];
            w[23] = BitLogic.SSIG1(w[21]) + w[16] + BitLogic.SSIG0(w[8]) + w[7];
            w[24] = BitLogic.SSIG1(w[22]) + w[17] + BitLogic.SSIG0(w[9]) + w[8];
            w[25] = BitLogic.SSIG1(w[23]) + w[18] + BitLogic.SSIG0(w[10]) + w[9];
            w[26] = BitLogic.SSIG1(w[24]) + w[19] + BitLogic.SSIG0(w[11]) + w[10];
            w[27] = BitLogic.SSIG1(w[25]) + w[20] + BitLogic.SSIG0(w[12]) + w[11];
            w[28] = BitLogic.SSIG1(w[26]) + w[21] + BitLogic.SSIG0(w[13]) + w[12];
            w[29] = BitLogic.SSIG1(w[27]) + w[22] + BitLogic.SSIG0(w[14]) + w[13];
            w[30] = BitLogic.SSIG1(w[28]) + w[23] + BitLogic.SSIG0(w[15]) + w[14];
            w[31] = BitLogic.SSIG1(w[29]) + w[24] + BitLogic.SSIG0(w[16]) + w[15];
            w[32] = BitLogic.SSIG1(w[30]) + w[25] + BitLogic.SSIG0(w[17]) + w[16];
            w[33] = BitLogic.SSIG1(w[31]) + w[26] + BitLogic.SSIG0(w[18]) + w[17];
            w[34] = BitLogic.SSIG1(w[32]) + w[27] + BitLogic.SSIG0(w[19]) + w[18];
            w[35] = BitLogic.SSIG1(w[33]) + w[28] + BitLogic.SSIG0(w[20]) + w[19];
            w[36] = BitLogic.SSIG1(w[34]) + w[29] + BitLogic.SSIG0(w[21]) + w[20];
            w[37] = BitLogic.SSIG1(w[35]) + w[30] + BitLogic.SSIG0(w[22]) + w[21];
            w[38] = BitLogic.SSIG1(w[36]) + w[31] + BitLogic.SSIG0(w[23]) + w[22];
            w[39] = BitLogic.SSIG1(w[37]) + w[32] + BitLogic.SSIG0(w[24]) + w[23];
            w[40] = BitLogic.SSIG1(w[38]) + w[33] + BitLogic.SSIG0(w[25]) + w[24];
            w[41] = BitLogic.SSIG1(w[39]) + w[34] + BitLogic.SSIG0(w[26]) + w[25];
            w[42] = BitLogic.SSIG1(w[40]) + w[35] + BitLogic.SSIG0(w[27]) + w[26];
            w[43] = BitLogic.SSIG1(w[41]) + w[36] + BitLogic.SSIG0(w[28]) + w[27];
            w[44] = BitLogic.SSIG1(w[42]) + w[37] + BitLogic.SSIG0(w[29]) + w[28];
            w[45] = BitLogic.SSIG1(w[43]) + w[38] + BitLogic.SSIG0(w[30]) + w[29];
            w[46] = BitLogic.SSIG1(w[44]) + w[39] + BitLogic.SSIG0(w[31]) + w[30];
            w[47] = BitLogic.SSIG1(w[45]) + w[40] + BitLogic.SSIG0(w[32]) + w[31];
            w[48] = BitLogic.SSIG1(w[46]) + w[41] + BitLogic.SSIG0(w[33]) + w[32];
            w[49] = BitLogic.SSIG1(w[47]) + w[42] + BitLogic.SSIG0(w[34]) + w[33];
            w[50] = BitLogic.SSIG1(w[48]) + w[43] + BitLogic.SSIG0(w[35]) + w[34];
            w[51] = BitLogic.SSIG1(w[49]) + w[44] + BitLogic.SSIG0(w[36]) + w[35];
            w[52] = BitLogic.SSIG1(w[50]) + w[45] + BitLogic.SSIG0(w[37]) + w[36];
            w[53] = BitLogic.SSIG1(w[51]) + w[46] + BitLogic.SSIG0(w[38]) + w[37];
            w[54] = BitLogic.SSIG1(w[52]) + w[47] + BitLogic.SSIG0(w[39]) + w[38];
            w[55] = BitLogic.SSIG1(w[53]) + w[48] + BitLogic.SSIG0(w[40]) + w[39];
            w[56] = BitLogic.SSIG1(w[54]) + w[49] + BitLogic.SSIG0(w[41]) + w[40];
            w[57] = BitLogic.SSIG1(w[55]) + w[50] + BitLogic.SSIG0(w[42]) + w[41];
            w[58] = BitLogic.SSIG1(w[56]) + w[51] + BitLogic.SSIG0(w[43]) + w[42];
            w[59] = BitLogic.SSIG1(w[57]) + w[52] + BitLogic.SSIG0(w[44]) + w[43];
            w[60] = BitLogic.SSIG1(w[58]) + w[53] + BitLogic.SSIG0(w[45]) + w[44];
            w[61] = BitLogic.SSIG1(w[59]) + w[54] + BitLogic.SSIG0(w[46]) + w[45];
            w[62] = BitLogic.SSIG1(w[60]) + w[55] + BitLogic.SSIG0(w[47]) + w[46];
            w[63] = BitLogic.SSIG1(w[61]) + w[56] + BitLogic.SSIG0(w[48]) + w[47];
           
        }


        public static byte[] GetPadding(long messageLengthInBytes)
        {
            int paddingLenght = 64 - (int)(messageLengthInBytes % 64);            
            //padding do not fit in last block, need to create next
            if (paddingLenght < 9) paddingLenght += 64;

            byte[] padding = new byte[paddingLenght];

            padding[0] = 0x80;
            long totalBitLength = 8 * messageLengthInBytes;
            BinConverter.ToBytesBE(padding, paddingLenght - 8, totalBitLength);

            return padding;
        }

        internal class BitLogic
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public static uint CH(uint x, uint y, uint z)
            {
                return (x & y) ^ ((~x) & z);
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public static uint MAJ(uint x, uint y, uint z)
            {
                return (x & y) ^ (x & z) ^ (y & z);
            }
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public static uint BSIG0(uint x)
            {
                return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
            }
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public static uint BSIG1(uint x)
            {
                return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
            }
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public static uint SSIG0(uint x)
            {
                return ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3);
            }
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public static uint SSIG1(uint x)
            {
                return ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10);
            }
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public static uint ROTR(uint x, int v)
            {
                return (x >> v) | (x << (32 - v));
            }
        }
    }
}


/*

[without ptrs, START POINT, NO OPTIMIZATIONS] 
10 times average: 4545

[ptrs ony on vars]
10 times average: 4482

[unwind schedule buffer] 
10 times average: 4388
[after Attribute: "MethodImpl-aggressive inlining" ON:
BitLogic methods AND PrepareMessageScheduleBuffer() ]
!WOW!
10 times average: 2545

[after unwind loop: new method created: Hash64ByteBlock]
10 times average: 2790 -> not so good, event with unwinded,

Notes: 
PrepareMessageScheduleBuffer: Unwind needed, better performance
[MethodImp.AggressiveInlining]: Attribute needed, better performance
Hash64ByteBlock: Do not unwind this loop, performance after unwind even worst
pointers on 'vars' instead of managed array: not sure if any difference, 
but may be important when other methods are called

Tested on buffer of size: 149 MB 
This buffer was hashed 10 times, results in miliseconds are below (for arctium and for System.Cryptography implementation)
[Arctium SHA2_256]
(hashing time of some buffer, in ms)
2143
1922
1891
1880
1886
1881
1890
1879
1878
1878
0
EA-88-18-2D-55-4F-3D-DF-16-5F-6B-1B-C1-3C-57-2A-DC-95-0D-AE-0D-1F-13-70-02-72-79-C0-DC-EA-C3-53

[System.Cryptography SHA256]
1137
1140
1127
1132
1130
1133
1132
1125
1132
1127
0
EA-88-18-2D-55-4F-3D-DF-16-5F-6B-1B-C1-3C-57-2A-DC-95-0D-AE-0D-1F-13-70-02-72-79-C0-DC-EA-C3-53
     */
