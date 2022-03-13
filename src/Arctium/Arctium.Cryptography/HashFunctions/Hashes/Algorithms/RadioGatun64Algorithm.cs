using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Shared.Helpers;
using Arctium.Shared.Helpers.Binary;
using System.Runtime.CompilerServices;

namespace Arctium.Cryptography.HashFunctions.Hashes.Algorithms
{
    public static class RadioGatun64Algorithm
    {
        // Number of Blank Rounds
        const int Nb = 16;

        public class State
        {
            public ulong[] a;
            public ulong[] b;
            public ulong[] A;
            public ulong[] B;
        }

        public static State Init()
        {
            State state = new State();
            state.a = new ulong[19];
            state.b = new ulong[3 * 13];
            state.A = new ulong[19];
            state.B = new ulong[3 * 13];

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
            MemMap.ToBytes2ULongLE(state.a, 1, buffer, offset);
            R(state);
            MemMap.ToBytes2ULongLE(state.a, 1, buffer, offset + 16);
        }

        public static void Process192BitBlocks(State state, byte[] buffer, long offset, long length)
        {
            ulong[] input = new ulong[3];

            for (long j = offset; j < offset + length; j += 24)
            {
                MemMap.ToULong24BytesLE(buffer, j, input, 0);

                state.b[0] ^= input[0];
                state.b[1] ^= input[1];
                state.b[2] ^= input[2];
                state.a[0 + 16] ^= input[0];
                state.a[1 + 16] ^= input[1];
                state.a[2 + 16] ^= input[2];

                R(state);
            }
        }

        static void R(State state)
        {
            ulong[] B = state.B;
            ulong[] A = state.A;
            ulong[] b = state.b;
            ulong[] a = state.a;

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

            for (int i = 0; i < 19; i++) a[i] = BinOps.ROR(A[(7 * i) % 19], ((i * (i + 1)) / 2) % 64);
            for (int i = 0; i < 19; i++) A[i] = a[i] ^ a[(i + 1) % 19] ^ a[(i + 4) % 19];
            A[0] ^= 1;

            for (int i = 0; i < 3; i++) A[i + 13] ^= b[(3 * 12) + i];

            ulong[] aCpy = state.a;
            ulong[] bCpy = state.b;

            state.a = A;
            state.b = B;
            state.A = aCpy;
            state.B = bCpy;
        }


        public static void ProcessLastBlock(State state, byte[] buffer, long offset, long length)
        {
            byte[] lastBlock;

            if (length < 24)
            {
                lastBlock = new byte[24];

            MemCpy.Copy(buffer, offset, lastBlock, 0, length);

            lastBlock[length] = 0x01;
            }
            else
            {
                lastBlock = buffer;
                // lastBlock = new byte[48];
            }


            Process192BitBlocks(state, lastBlock, 0, lastBlock.Length);
        }
    }
}
