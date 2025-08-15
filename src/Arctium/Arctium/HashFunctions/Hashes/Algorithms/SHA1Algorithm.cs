/*
 * SHA1 Algorithm
 * - - - - -
 * Implemented by NeuroXiq 2021
 * */

using System;
using System.IO;
using System.Collections.Generic;
using System.Text;
using Arctium.Shared;

namespace Arctium.Cryptography.HashFunctions.Hashes.Algorithms
{
    public static unsafe class SHA1Algorithm
    {
        public class Context 
        {
            public uint[] H;
            public ulong TotalMessageLengthInBytes;
        }

        public static Context InitializeContext()
        {
            Context c = new Context();
            c.H = new uint[5];

            ResetContext(c);

            return c;
        }

        public static void ResetContext(Context c)
        {
            c.H[0] = 0x67452301;
            c.H[1] = 0xEFCDAB89;
            c.H[2] = 0x98BADCFE;
            c.H[3] = 0x10325476;
            c.H[4] = 0xC3D2E1F0;

            c.TotalMessageLengthInBytes = 0;
        }

        public static void HashFullBlocks(Context context, byte* buffer, long offset, long length)
        {
            for (long i = offset; i < length; i += 64)
            {
                HashBlock(context, (buffer + i));
                context.TotalMessageLengthInBytes += 64;
            }
        }

        public static void HashLastBlock(Context context, byte[] lastBlock, long offset, long length)
        {
            byte[] last;
            context.TotalMessageLengthInBytes += (ulong)length;

            if (length < 56)
            {
                last = new byte[64];
            }
            else
            {
                last = new byte[128];
            }

            Buffer.BlockCopy(lastBlock, (int)offset, last, 0, (int)length);
            last[length] = 0x80;
            MemMap.ToBytes1ULongBE((ulong)context.TotalMessageLengthInBytes * 8, last, last.Length - 8);

            fixed (byte* b = &last[0])
            {
                
                HashFullBlocks(context, b, 0, last.Length);
            }
        }

        public static void GetHash(Context context, byte[] buffer, long offset)
        {
            MemMap.ToBytes5UIntBE(context.H, 0, buffer, offset);
        }

        private static uint K(int t)
        {
            if ( 0 <= t && t < 20) return 0x5A827999;
            if (20 <= t && t < 40) return 0x6ED9EBA1;
            if (40 <= t && t < 60) return 0x8F1BBCDC;
            if (60 <= t && t < 80) return 0xCA62C1D6;

            throw new Exception();
        }

        private static uint F(int t, uint b, uint c, uint d)
        {
            if ( 0 <= t && t < 20) return (b & c) | ((~b) & d);
            if (20 <= t && t < 40) return b ^ c ^ d;
            if (40 <= t && t < 60) return (b & c) | (b & d) | (c & d);
            if (60 <= t && t < 80) return b ^ c ^ d;

            throw new Exception();
        }

        private static void HashBlock(Context context, byte* buffer)
        {
            uint* W = stackalloc uint[80];
            uint A, B, C, D, E, temp;
            MemMap.ToUInt64BytesBE(buffer, 0, W, 0);

            for (int t = 16; t < 80; t++) W[t] = BinOps.ROL(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);

            A = context.H[0]; B = context.H[1];
            C = context.H[2]; D = context.H[3];
            E = context.H[4];

            for (int t = 0; t < 80; t++)
            {
                temp = BinOps.ROL(A, 5) + F(t, B, C, D) + E + W[t] + K(t);
                E = D; D = C; C = BinOps.ROL(B, 30); B = A; A = temp;
            }

            context.H[0] += A;
            context.H[1] += B;
            context.H[2] += C;
            context.H[3] += D;
            context.H[4] += E;
        }
    }
}
