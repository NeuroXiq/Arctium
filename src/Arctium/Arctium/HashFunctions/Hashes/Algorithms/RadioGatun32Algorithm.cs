using System;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Shared.Helpers;
using Arctium.Shared.Helpers.Binary;
using System.Runtime.CompilerServices;

namespace Arctium.Cryptography.HashFunctions.Hashes.Algorithms
{
    public static unsafe class RadioGatun32Algorithm
    {
        // Number of Blank Rounds
        const int Nb = 16;

        public class State
        {
            public uint[] a;
            public uint[] b;
            public uint[] A;
            public uint[] B;
        }

        public static State Init()
        {
            State state = new State();
            state.a = new uint[19];
            state.b = new uint[3 * 13];
            state.A = new uint[19];
            state.B = new uint[3 * 13];

            Reset(state);

            return state;
        }

        public static void Reset(State state)
        {
            MemOps.Memset(state.a, 0, state.a.Length, 0);
            MemOps.Memset(state.b, 0, state.b.Length, 0);
        }

        public static void GetHash(State state, byte[] buffer, long offset)
        {
            for (int j = 0; j < Nb; j++) R(state);
            R(state);
            MemMap.ToBytes2UIntLE(state.a, 1, buffer, offset);
            R(state);
            MemMap.ToBytes2UIntLE(state.a, 1, buffer, offset + 8);
            R(state);
            MemMap.ToBytes2UIntLE(state.a, 1, buffer, offset + 16);
            R(state);
            MemMap.ToBytes2UIntLE(state.a, 1, buffer, offset + 24);
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization | MethodImplOptions.AggressiveInlining)]
        public static void Process96BitBlocks(State state, byte[] buffer, long offset, long length)
        {
            uint* input = stackalloc uint[3];
            uint* a = stackalloc uint[19];
            uint* b = stackalloc uint[13 * 3];
            uint* A = stackalloc uint[19];
            uint* B = stackalloc uint[13 * 3];

            fixed (byte* pBuffer = &buffer[offset])
            {
                MemCpy.Copy(state.a, a);
                MemCpy.Copy(state.b, b);

                for (long j = 0; j < length; j += 12)
                {
                    MemMap.ToUInt24BytesLE(pBuffer + j, input);

                    b[0] ^= input[0];
                    b[1] ^= input[1];
                    b[2] ^= input[2];
                    a[0 + 16] ^= input[0];
                    a[1 + 16] ^= input[1];
                    a[2 + 16] ^= input[2];

                    R_Optimized(state, a, b, A, B);

                    uint *aCpy = a;
                    uint* bCpy = b;

                    a = A;
                    b = B;

                    A = aCpy;
                    B = bCpy;
                }

                MemCpy.Copy(a, 0, state.a, 0, state.a.Length);
                MemCpy.Copy(b, 0, state.b, 0, state.b.Length);
            }
        }

        //
        // Exactly same as 'R' method but optimized
        // 
        [MethodImpl(MethodImplOptions.AggressiveOptimization | MethodImplOptions.AggressiveInlining)]
        static void R_Optimized(State state, uint* a, uint* b, uint* A, uint* B)
        {
            B[0] = b[36];
            B[1] = b[37];
            B[2] = b[38];
            B[3] = b[0];
            B[4] = b[1];
            B[5] = b[2];
            B[6] = b[3];
            B[7] = b[4];
            B[8] = b[5];
            B[9] = b[6];
            B[10] = b[7];
            B[11] = b[8];
            B[12] = b[9];
            B[13] = b[10];
            B[14] = b[11];
            B[15] = b[12];
            B[16] = b[13];
            B[17] = b[14];
            B[18] = b[15];
            B[19] = b[16];
            B[20] = b[17];
            B[21] = b[18];
            B[22] = b[19];
            B[23] = b[20];
            B[24] = b[21];
            B[25] = b[22];
            B[26] = b[23];
            B[27] = b[24];
            B[28] = b[25];
            B[29] = b[26];
            B[30] = b[27];
            B[31] = b[28];
            B[32] = b[29];
            B[33] = b[30];
            B[34] = b[31];
            B[35] = b[32];
            B[36] = b[33];
            B[37] = b[34];
            B[38] = b[35];
            B[3] ^= a[1];
            B[7] ^= a[2];
            B[11] ^= a[3];
            B[12] ^= a[4];
            B[16] ^= a[5];
            B[20] ^= a[6];
            B[21] ^= a[7];
            B[25] ^= a[8];
            B[29] ^= a[9];
            B[30] ^= a[10];
            B[34] ^= a[11];
            B[38] ^= a[12];
            A[0] = a[0] ^ (a[1] | (~a[2]));
            A[1] = a[1] ^ (a[2] | (~a[3]));
            A[2] = a[2] ^ (a[3] | (~a[4]));
            A[3] = a[3] ^ (a[4] | (~a[5]));
            A[4] = a[4] ^ (a[5] | (~a[6]));
            A[5] = a[5] ^ (a[6] | (~a[7]));
            A[6] = a[6] ^ (a[7] | (~a[8]));
            A[7] = a[7] ^ (a[8] | (~a[9]));
            A[8] = a[8] ^ (a[9] | (~a[10]));
            A[9] = a[9] ^ (a[10] | (~a[11]));
            A[10] = a[10] ^ (a[11] | (~a[12]));
            A[11] = a[11] ^ (a[12] | (~a[13]));
            A[12] = a[12] ^ (a[13] | (~a[14]));
            A[13] = a[13] ^ (a[14] | (~a[15]));
            A[14] = a[14] ^ (a[15] | (~a[16]));
            A[15] = a[15] ^ (a[16] | (~a[17]));
            A[16] = a[16] ^ (a[17] | (~a[18]));
            A[17] = a[17] ^ (a[18] | (~a[0]));
            A[18] = a[18] ^ (a[0] | (~a[1]));
            a[0] = BinOps.ROR(A[0], 0);
            a[1] = BinOps.ROR(A[7], 1);
            a[2] = BinOps.ROR(A[14], 3);
            a[3] = BinOps.ROR(A[2], 6);
            a[4] = BinOps.ROR(A[9], 10);
            a[5] = BinOps.ROR(A[16], 15);
            a[6] = BinOps.ROR(A[4], 21);
            a[7] = BinOps.ROR(A[11], 28);
            a[8] = BinOps.ROR(A[18], 4);
            a[9] = BinOps.ROR(A[6], 13);
            a[10] = BinOps.ROR(A[13], 23);
            a[11] = BinOps.ROR(A[1], 2);
            a[12] = BinOps.ROR(A[8], 14);
            a[13] = BinOps.ROR(A[15], 27);
            a[14] = BinOps.ROR(A[3], 9);
            a[15] = BinOps.ROR(A[10], 24);
            a[16] = BinOps.ROR(A[17], 8);
            a[17] = BinOps.ROR(A[5], 25);
            a[18] = BinOps.ROR(A[12], 11);
            A[0] = a[0] ^ a[1] ^ a[4];
            A[1] = a[1] ^ a[2] ^ a[5];
            A[2] = a[2] ^ a[3] ^ a[6];
            A[3] = a[3] ^ a[4] ^ a[7];
            A[4] = a[4] ^ a[5] ^ a[8];
            A[5] = a[5] ^ a[6] ^ a[9];
            A[6] = a[6] ^ a[7] ^ a[10];
            A[7] = a[7] ^ a[8] ^ a[11];
            A[8] = a[8] ^ a[9] ^ a[12];
            A[9] = a[9] ^ a[10] ^ a[13];
            A[10] = a[10] ^ a[11] ^ a[14];
            A[11] = a[11] ^ a[12] ^ a[15];
            A[12] = a[12] ^ a[13] ^ a[16];
            A[13] = a[13] ^ a[14] ^ a[17];
            A[14] = a[14] ^ a[15] ^ a[18];
            A[15] = a[15] ^ a[16] ^ a[0];
            A[16] = a[16] ^ a[17] ^ a[1];
            A[17] = a[17] ^ a[18] ^ a[2];
            A[18] = a[18] ^ a[0] ^ a[3];
            A[0] ^= 1;
            A[13] ^= b[36];
            A[14] ^= b[37];
            A[15] ^= b[38];
        }

        // Not optimized version of 'R' function
        static void R(State state)
        {
            uint[] B = state.B;
            uint[] A = state.A;
            uint[] b = state.b;
            uint[] a = state.a;

            for (int i = 0; i < 3 * 13; i++)
            {
                B[i] = b[(i - 3 + (3 * 13)) % (3 * 13)];
            }

            for (int i = 0; i < 12; i++)
            {
                B[(3 * (i + 1)) + (i % 3)] ^= a[i + 1];
            }

            for (int i = 0; i < 19; i++)
            {
                A[i] = a[i] ^ (a[(i + 1) % 19] | (~a[(i + 2) % 19]));
            }

            for (int i = 0; i < 19; i++) a[i] = BinOps.ROR(A[(7 * i) % 19], ((i * (i + 1)) / 2) % 32);
            for (int i = 0; i < 19; i++) A[i] = a[i] ^ a[(i + 1) % 19] ^ a[(i + 4) % 19];
            A[0] ^= 1;

            for (int i = 0; i < 3; i++) A[i + 13] ^= b[(3 * 12) + i];

            uint[] aCpy = state.a;
            uint[] bCpy = state.b;

            state.a = A;
            state.b = B;
            state.A = aCpy;
            state.B = bCpy;
        }


        public static void ProcessLastBlock(State state, byte[] buffer, long offset, long length)
        {
            byte[] lastBlock = new byte[12];

            MemCpy.Copy(buffer, offset, lastBlock, 0, length);
            lastBlock[length] = 0x01;

            Process96BitBlocks(state, lastBlock, 0, lastBlock.Length);
        }

        

        /* ------------------------------------------------ END OF ALGORITHM -----------------------------------------------
         * TOOLS
         * 
         * 
         */

        //
        // Helper method to generate optimized version of 'R' function
        // Nothing special - unwinded for loops
        //

        static void Generate()
        {
            for (int i = 0; i < 3 * 13; i++)
            {
                Console.WriteLine($"B[{i}] = b[{(i - 3 + (3 * 13)) % (3 * 13)}];");
            }

            for (int i = 0; i < 12; i++)
            {
                Console.WriteLine($"B[{(3 * (i + 1)) + (i % 3)}] ^= a[{i + 1}];");
            }

            for (int i = 0; i < 19; i++)
            {
                Console.WriteLine($"A[{i}] = a[{i}] ^ (a[{(i + 1) % 19}] | (~a[{(i + 2) % 19}]));");
            }

            for (int i = 0; i < 19; i++) Console.WriteLine($"a[{i}] = BinOps.ROR(A[{(7 * i) % 19}], {((i * (i + 1)) / 2) % 32});");
            for (int i = 0; i < 19; i++) Console.WriteLine($"A[{i}] = a[{i}] ^ a[{(i + 1) % 19}] ^ a[{(i + 4) % 19}];");
            Console.WriteLine($"A[0] ^= 1;");

            for (int i = 0; i < 3; i++) Console.WriteLine($"A[{i + 13}] ^= b[{(3 * 12) + i}];");
        }

    }
}
