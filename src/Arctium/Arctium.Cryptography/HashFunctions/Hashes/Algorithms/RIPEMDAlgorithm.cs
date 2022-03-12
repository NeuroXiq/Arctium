using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Shared.Helpers.Binary;

namespace Arctium.Cryptography.HashFunctions.Hashes.Algorithms
{
    public static class RIPEMDAlgorithm
    {
        public class State
        {
            public ulong MsgLen;
            public uint[] H;
        }

        public static State Init()
        {
            State state = new State();
            state.H = new uint[5];

            Reset(state);

            return state;
        }

        public static void Reset(State state)
        {
            state.MsgLen = 0;
            state.H[0] = 0x67452301;
            state.H[1] = 0xefcdab89;
            state.H[2] = 0x98BADCFE;
            state.H[3] = 0x10325476;
            state.H[4] = 0xC3D2E1F0;
        }

        public static void GetHash(State state, byte[] outputBuffer, long outputOffset)
        {
            MemMap.ToBytes5UIntLE(state.H, 0, outputBuffer, outputOffset);
        }

        public static void Process512BitBlocks(State state, byte[] buffer, long offset, long length)
        {
            uint[] block = new uint[16];

            for (long i = offset; i < length + offset; i += 64)
            {
                MemMap.ToUInt64BytesLE(buffer, i, block, 0);

                ProcessBlock(state.H, block);

                state.MsgLen += 64;
            }
        }

        static void ProcessBlock(uint[] h, uint[] input)
        {
            uint a = h[0],
            b  = h[1],
            c  = h[2],
            d  = h[3],
            e  = h[4],
            ap = h[0],
            bp = h[1],
            cp = h[2],
            dp = h[3],
            ep = h[4],
            t = 0;
            
            for (int i = 0; i < 80; i++)
            {
                t = BinOps.ROL(a + f(i, b, c, d) + input[r[i]] + K[i/16], s[i]) + e;
                a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                t = BinOps.ROL(ap + f(79 - i, bp, cp, dp) + input[rp[i]] + Kp[i / 16], sp[i]) + ep;
                ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
            }

            t = h[1] + c + dp; h[1] = h[2] + d + ep; h[2] = h[3] + e + ap;
            h[3] = h[4] + a + bp; h[4] = h[0] + b + cp; h[0] = t;
        }

        static uint f(int j, uint x, uint y, uint z)
        {
            uint r;
            
            if (j < 16)
            {
                r =  x ^ y ^ z;
            }
            else if (j < 32)
            {
                r = (x & y) | ((~x) & z);
            }
            else if (j < 48)
            {
                r = (x | ( ~y)) ^ z;
            }
            else if (j < 64)
            {
                r = (x & z)  | (y & (~z));
            }
            else
            {
                r = x ^ (y | (~z));
            }

            return r;
        }

        public static void ProcessLastBlock(State state, byte[] buffer, long offset, long length)
        {
            byte[] lastBlock;
            ulong lenInBits = ((ulong)length + state.MsgLen) * 8;
            int lenOffset;

            if (length < 64 - 8 - 1)
            {
                lastBlock = new byte[64];
            }
            else
            {
                lastBlock = new byte[128];
            }

            MemCpy.Copy(buffer, offset, lastBlock, 0, length);
            lenOffset = lastBlock.Length - 8;
            
            lastBlock[length] = 0x80;

            lastBlock[lenOffset + 3] = (byte)(((lenInBits & 0x00000000FF000000) >> 24));
            lastBlock[lenOffset + 2] = (byte)(((lenInBits & 0x0000000000FF0000) >> 16));
            lastBlock[lenOffset + 1] = (byte)(((lenInBits & 0x000000000000FF00) >> 08));
            lastBlock[lenOffset + 0] = (byte)(((lenInBits & 0x00000000000000FF) >> 00));

            lastBlock[lenOffset + 7] = (byte)(((lenInBits & 0xFF00000000000000) >> 56));
            lastBlock[lenOffset + 6] = (byte)(((lenInBits & 0x00FF000000000000) >> 48));
            lastBlock[lenOffset + 5] = (byte)(((lenInBits & 0x0000FF0000000000) >> 40));
            lastBlock[lenOffset + 4] = (byte)(((lenInBits & 0x000000FF00000000) >> 32));

            Process512BitBlocks(state, lastBlock, 0, lastBlock.Length);
        }

        static readonly int[] s = new int[]
        {
            11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
            7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
            11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
            11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
            9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
        };

        static readonly int[] sp = new int[]
        {
            8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
            9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
            9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
            15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
            8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
        };

        static readonly uint[] K = new uint[]
        {
            0x00000000,
            0x5A827999,
            0x6ED9EBA1,
            0x8F1BBCDC,
            0xA953FD4E,
        };

        static readonly uint[] Kp = new uint[] 
        {
            0x50A28BE6,
            0x5C4DD124,
            0x6D703EF3,
            0x7A6D76E9,
            0x00000000,
        };

        static readonly byte[] r = new byte[]
        {
            0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
            7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
            3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
            1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
            4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
        };


        static readonly byte[] rp = new byte[]
        {
            5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
            6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
            15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
            8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
            12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
        };
    }
}
