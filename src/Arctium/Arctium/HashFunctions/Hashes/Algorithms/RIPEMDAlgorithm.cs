/*
 * Algorithm Authors:
 * 
 *  Hans Dobbertin1 Antoon Bosselaers2 Bart Preneel2??
 *  1 German Information Security Agency
 *  P.O. Box 20 03 63, D-53133 Bonn, Germany
 *  dobbertin@skom.rhein.de
 *  2 Katholieke Universiteit Leuven, ESAT-COSIC
 *  K. Mercierlaan 94, B-3001 Heverlee, Belgium
 *  {antoon.bosselaers,bart.preneel}@esat.kuleuven.ac.be
 *  
 *  Implemented by NeuroXiq (Arctium) 2022
 */

using System.Runtime.CompilerServices;
using Arctium.Shared;

namespace Arctium.Cryptography.HashFunctions.Hashes.Algorithms
{
    public static unsafe class RIPEMDAlgorithm
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

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        public static void Process512BitBlocks(State state, byte[] buffer, long offset, long length)
        {
            uint[] block = new uint[16];

            fixed (uint* input = &block[0], h = &state.H[0])
            fixed (byte* inBuf = &buffer[0])
            {
                for (long curOffset = offset; curOffset < length + offset; curOffset += 64)
                {
                    MemMap.ToUInt64BytesLE(inBuf + (curOffset), input);

                    uint a = h[0],
                    b = h[1],
                    c = h[2],
                    d = h[3],
                    e = h[4],
                    ap = h[0],
                    bp = h[1],
                    cp = h[2],
                    dp = h[3],
                    ep = h[4],
                    t = 0;

                    t = BinOps.ROL(a + (b ^ c ^ d) + input[0] + 0x00000000, 11) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + (bp ^ (cp | (~dp))) + input[5] + 0x50A28BE6, 8) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + (b ^ c ^ d) + input[1] + 0x00000000, 14) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + (bp ^ (cp | (~dp))) + input[14] + 0x50A28BE6, 9) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + (b ^ c ^ d) + input[2] + 0x00000000, 15) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + (bp ^ (cp | (~dp))) + input[7] + 0x50A28BE6, 9) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + (b ^ c ^ d) + input[3] + 0x00000000, 12) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + (bp ^ (cp | (~dp))) + input[0] + 0x50A28BE6, 11) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + (b ^ c ^ d) + input[4] + 0x00000000, 5) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + (bp ^ (cp | (~dp))) + input[9] + 0x50A28BE6, 13) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + (b ^ c ^ d) + input[5] + 0x00000000, 8) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + (bp ^ (cp | (~dp))) + input[2] + 0x50A28BE6, 15) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + (b ^ c ^ d) + input[6] + 0x00000000, 7) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + (bp ^ (cp | (~dp))) + input[11] + 0x50A28BE6, 15) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + (b ^ c ^ d) + input[7] + 0x00000000, 9) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + (bp ^ (cp | (~dp))) + input[4] + 0x50A28BE6, 5) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + (b ^ c ^ d) + input[8] + 0x00000000, 11) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + (bp ^ (cp | (~dp))) + input[13] + 0x50A28BE6, 7) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + (b ^ c ^ d) + input[9] + 0x00000000, 13) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + (bp ^ (cp | (~dp))) + input[6] + 0x50A28BE6, 7) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + (b ^ c ^ d) + input[10] + 0x00000000, 14) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + (bp ^ (cp | (~dp))) + input[15] + 0x50A28BE6, 8) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + (b ^ c ^ d) + input[11] + 0x00000000, 15) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + (bp ^ (cp | (~dp))) + input[8] + 0x50A28BE6, 11) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + (b ^ c ^ d) + input[12] + 0x00000000, 6) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + (bp ^ (cp | (~dp))) + input[1] + 0x50A28BE6, 14) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + (b ^ c ^ d) + input[13] + 0x00000000, 7) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + (bp ^ (cp | (~dp))) + input[10] + 0x50A28BE6, 14) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + (b ^ c ^ d) + input[14] + 0x00000000, 9) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + (bp ^ (cp | (~dp))) + input[3] + 0x50A28BE6, 12) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + (b ^ c ^ d) + input[15] + 0x00000000, 8) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + (bp ^ (cp | (~dp))) + input[12] + 0x50A28BE6, 6) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b & c) | ((~b) & d)) + input[7] + 0x5A827999, 7) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp & dp) | (cp & (~dp))) + input[6] + 0x5C4DD124, 9) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b & c) | ((~b) & d)) + input[4] + 0x5A827999, 6) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp & dp) | (cp & (~dp))) + input[11] + 0x5C4DD124, 13) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b & c) | ((~b) & d)) + input[13] + 0x5A827999, 8) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp & dp) | (cp & (~dp))) + input[3] + 0x5C4DD124, 15) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b & c) | ((~b) & d)) + input[1] + 0x5A827999, 13) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp & dp) | (cp & (~dp))) + input[7] + 0x5C4DD124, 7) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b & c) | ((~b) & d)) + input[10] + 0x5A827999, 11) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp & dp) | (cp & (~dp))) + input[0] + 0x5C4DD124, 12) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b & c) | ((~b) & d)) + input[6] + 0x5A827999, 9) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp & dp) | (cp & (~dp))) + input[13] + 0x5C4DD124, 8) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b & c) | ((~b) & d)) + input[15] + 0x5A827999, 7) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp & dp) | (cp & (~dp))) + input[5] + 0x5C4DD124, 9) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b & c) | ((~b) & d)) + input[3] + 0x5A827999, 15) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp & dp) | (cp & (~dp))) + input[10] + 0x5C4DD124, 11) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b & c) | ((~b) & d)) + input[12] + 0x5A827999, 7) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp & dp) | (cp & (~dp))) + input[14] + 0x5C4DD124, 7) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b & c) | ((~b) & d)) + input[0] + 0x5A827999, 12) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp & dp) | (cp & (~dp))) + input[15] + 0x5C4DD124, 7) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b & c) | ((~b) & d)) + input[9] + 0x5A827999, 15) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp & dp) | (cp & (~dp))) + input[8] + 0x5C4DD124, 12) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b & c) | ((~b) & d)) + input[5] + 0x5A827999, 9) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp & dp) | (cp & (~dp))) + input[12] + 0x5C4DD124, 7) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b & c) | ((~b) & d)) + input[2] + 0x5A827999, 11) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp & dp) | (cp & (~dp))) + input[4] + 0x5C4DD124, 6) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b & c) | ((~b) & d)) + input[14] + 0x5A827999, 7) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp & dp) | (cp & (~dp))) + input[9] + 0x5C4DD124, 15) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b & c) | ((~b) & d)) + input[11] + 0x5A827999, 13) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp & dp) | (cp & (~dp))) + input[1] + 0x5C4DD124, 13) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b & c) | ((~b) & d)) + input[8] + 0x5A827999, 12) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp & dp) | (cp & (~dp))) + input[2] + 0x5C4DD124, 11) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b | (~c)) ^ d) + input[3] + 0x6ED9EBA1, 11) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp | (~cp)) ^ dp) + input[15] + 0x6D703EF3, 9) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b | (~c)) ^ d) + input[10] + 0x6ED9EBA1, 13) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp | (~cp)) ^ dp) + input[5] + 0x6D703EF3, 7) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b | (~c)) ^ d) + input[14] + 0x6ED9EBA1, 6) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp | (~cp)) ^ dp) + input[1] + 0x6D703EF3, 15) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b | (~c)) ^ d) + input[4] + 0x6ED9EBA1, 7) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp | (~cp)) ^ dp) + input[3] + 0x6D703EF3, 11) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b | (~c)) ^ d) + input[9] + 0x6ED9EBA1, 14) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp | (~cp)) ^ dp) + input[7] + 0x6D703EF3, 8) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b | (~c)) ^ d) + input[15] + 0x6ED9EBA1, 9) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp | (~cp)) ^ dp) + input[14] + 0x6D703EF3, 6) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b | (~c)) ^ d) + input[8] + 0x6ED9EBA1, 13) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp | (~cp)) ^ dp) + input[6] + 0x6D703EF3, 6) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b | (~c)) ^ d) + input[1] + 0x6ED9EBA1, 15) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp | (~cp)) ^ dp) + input[9] + 0x6D703EF3, 14) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b | (~c)) ^ d) + input[2] + 0x6ED9EBA1, 14) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp | (~cp)) ^ dp) + input[11] + 0x6D703EF3, 12) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b | (~c)) ^ d) + input[7] + 0x6ED9EBA1, 8) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp | (~cp)) ^ dp) + input[8] + 0x6D703EF3, 13) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b | (~c)) ^ d) + input[0] + 0x6ED9EBA1, 13) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp | (~cp)) ^ dp) + input[12] + 0x6D703EF3, 5) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b | (~c)) ^ d) + input[6] + 0x6ED9EBA1, 6) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp | (~cp)) ^ dp) + input[2] + 0x6D703EF3, 14) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b | (~c)) ^ d) + input[13] + 0x6ED9EBA1, 5) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp | (~cp)) ^ dp) + input[10] + 0x6D703EF3, 13) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b | (~c)) ^ d) + input[11] + 0x6ED9EBA1, 12) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp | (~cp)) ^ dp) + input[0] + 0x6D703EF3, 13) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b | (~c)) ^ d) + input[5] + 0x6ED9EBA1, 7) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp | (~cp)) ^ dp) + input[4] + 0x6D703EF3, 7) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b | (~c)) ^ d) + input[12] + 0x6ED9EBA1, 5) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp | (~cp)) ^ dp) + input[13] + 0x6D703EF3, 5) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b & d) | (c & (~d))) + input[1] + 0x8F1BBCDC, 11) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp & cp) | ((~bp) & dp)) + input[8] + 0x7A6D76E9, 15) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b & d) | (c & (~d))) + input[9] + 0x8F1BBCDC, 12) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp & cp) | ((~bp) & dp)) + input[6] + 0x7A6D76E9, 5) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b & d) | (c & (~d))) + input[11] + 0x8F1BBCDC, 14) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp & cp) | ((~bp) & dp)) + input[4] + 0x7A6D76E9, 8) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b & d) | (c & (~d))) + input[10] + 0x8F1BBCDC, 15) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp & cp) | ((~bp) & dp)) + input[1] + 0x7A6D76E9, 11) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b & d) | (c & (~d))) + input[0] + 0x8F1BBCDC, 14) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp & cp) | ((~bp) & dp)) + input[3] + 0x7A6D76E9, 14) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b & d) | (c & (~d))) + input[8] + 0x8F1BBCDC, 15) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp & cp) | ((~bp) & dp)) + input[11] + 0x7A6D76E9, 14) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b & d) | (c & (~d))) + input[12] + 0x8F1BBCDC, 9) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp & cp) | ((~bp) & dp)) + input[15] + 0x7A6D76E9, 6) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b & d) | (c & (~d))) + input[4] + 0x8F1BBCDC, 8) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp & cp) | ((~bp) & dp)) + input[0] + 0x7A6D76E9, 14) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b & d) | (c & (~d))) + input[13] + 0x8F1BBCDC, 9) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp & cp) | ((~bp) & dp)) + input[5] + 0x7A6D76E9, 6) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b & d) | (c & (~d))) + input[3] + 0x8F1BBCDC, 14) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp & cp) | ((~bp) & dp)) + input[12] + 0x7A6D76E9, 9) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b & d) | (c & (~d))) + input[7] + 0x8F1BBCDC, 5) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp & cp) | ((~bp) & dp)) + input[2] + 0x7A6D76E9, 12) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b & d) | (c & (~d))) + input[15] + 0x8F1BBCDC, 6) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp & cp) | ((~bp) & dp)) + input[13] + 0x7A6D76E9, 9) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b & d) | (c & (~d))) + input[14] + 0x8F1BBCDC, 8) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp & cp) | ((~bp) & dp)) + input[9] + 0x7A6D76E9, 12) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b & d) | (c & (~d))) + input[5] + 0x8F1BBCDC, 6) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp & cp) | ((~bp) & dp)) + input[7] + 0x7A6D76E9, 5) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b & d) | (c & (~d))) + input[6] + 0x8F1BBCDC, 5) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp & cp) | ((~bp) & dp)) + input[10] + 0x7A6D76E9, 15) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + ((b & d) | (c & (~d))) + input[2] + 0x8F1BBCDC, 12) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + ((bp & cp) | ((~bp) & dp)) + input[14] + 0x7A6D76E9, 8) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + (b ^ (c | (~d))) + input[4] + 0xA953FD4E, 9) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + (bp ^ cp ^ dp) + input[12] + 0x00000000, 8) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + (b ^ (c | (~d))) + input[0] + 0xA953FD4E, 15) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + (bp ^ cp ^ dp) + input[15] + 0x00000000, 5) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + (b ^ (c | (~d))) + input[5] + 0xA953FD4E, 5) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + (bp ^ cp ^ dp) + input[10] + 0x00000000, 12) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + (b ^ (c | (~d))) + input[9] + 0xA953FD4E, 11) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + (bp ^ cp ^ dp) + input[4] + 0x00000000, 9) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + (b ^ (c | (~d))) + input[7] + 0xA953FD4E, 6) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + (bp ^ cp ^ dp) + input[1] + 0x00000000, 12) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + (b ^ (c | (~d))) + input[12] + 0xA953FD4E, 8) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + (bp ^ cp ^ dp) + input[5] + 0x00000000, 5) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + (b ^ (c | (~d))) + input[2] + 0xA953FD4E, 13) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + (bp ^ cp ^ dp) + input[8] + 0x00000000, 14) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + (b ^ (c | (~d))) + input[10] + 0xA953FD4E, 12) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + (bp ^ cp ^ dp) + input[7] + 0x00000000, 6) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + (b ^ (c | (~d))) + input[14] + 0xA953FD4E, 5) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + (bp ^ cp ^ dp) + input[6] + 0x00000000, 8) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + (b ^ (c | (~d))) + input[1] + 0xA953FD4E, 12) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + (bp ^ cp ^ dp) + input[2] + 0x00000000, 13) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + (b ^ (c | (~d))) + input[3] + 0xA953FD4E, 13) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + (bp ^ cp ^ dp) + input[13] + 0x00000000, 6) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + (b ^ (c | (~d))) + input[8] + 0xA953FD4E, 14) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + (bp ^ cp ^ dp) + input[14] + 0x00000000, 5) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + (b ^ (c | (~d))) + input[11] + 0xA953FD4E, 11) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + (bp ^ cp ^ dp) + input[0] + 0x00000000, 15) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + (b ^ (c | (~d))) + input[6] + 0xA953FD4E, 8) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + (bp ^ cp ^ dp) + input[3] + 0x00000000, 13) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + (b ^ (c | (~d))) + input[15] + 0xA953FD4E, 5) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + (bp ^ cp ^ dp) + input[9] + 0x00000000, 11) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
                    t = BinOps.ROL(a + (b ^ (c | (~d))) + input[13] + 0xA953FD4E, 6) + e;
                    a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                    t = BinOps.ROL(ap + (bp ^ cp ^ dp) + input[11] + 0x00000000, 11) + ep;
                    ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;

                    t = h[1] + c + dp; h[1] = h[2] + d + ep; h[2] = h[3] + e + ap;
                    h[3] = h[4] + a + bp; h[4] = h[0] + b + cp; h[0] = t;

                    state.MsgLen += 64;
                }
            }
        }

        /*
         * Code used to generate expanded version
         * for now not better optimization found leaving code for future
         * if there is a better optimization
         */

        static void ProcessBlock(uint[] h, uint[] input)
        {
            uint a = h[0],
            b = h[1],
            c = h[2],
            d = h[3],
            e = h[4],
            ap = h[0],
            bp = h[1],
            cp = h[2],
            dp = h[3],
            ep = h[4],
            t = 0;

            for (int i = 0; i < 80; i++)
            {
                //Console.WriteLine($"t = BinOps.ROL(a + ({fs(i, "b", "c", "d")}) + input[{r[i]}] + 0x{K[i/16].ToString("X8")}, {s[i]}) + e;");
                //Console.WriteLine("a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;");
                //Console.WriteLine($"t = BinOps.ROL(ap + ({fs(79 - i, "bp", "cp", "dp")}) + input[{rp[i]}] + 0x{Kp[i / 16].ToString("X8")}, {sp[i]}) + ep;");
                //Console.WriteLine("ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;");
                //
                //t = BinOps.ROL(a + f(i, b, c, d) + input[r[i]] + K[i/16], s[i]) + e;
                //a = e; e = d; d = BinOps.ROL(c, 10); c = b; b = t;
                //t = BinOps.ROL(ap + f(79 - i, bp, cp, dp) + input[rp[i]] + Kp[i / 16], sp[i]) + ep;
                //ap = ep; ep = dp; dp = BinOps.ROL(cp, 10); cp = bp; bp = t;
            }

            t = h[1] + c + dp; h[1] = h[2] + d + ep; h[2] = h[3] + e + ap;
            h[3] = h[4] + a + bp; h[4] = h[0] + b + cp; h[0] = t;
        }


        static string fs(int j, string x, string y, string z)
        {
            if (j < 16)
            {
                return $"{x} ^ {y} ^ {z}";
            }
            else if (j < 32)
            {
                return $"({x} & {y}) | ((~{x}) & {z})";
            }
            else if (j < 48)
            {
                return $"({x} | (~{y})) ^ {z}";
            }
            else if (j < 64)
            {
                return $"({x} & {z}) | ({y} & (~{z}))";
            }
            else
            {
                return $"{x} ^ ({y} | (~{z}))";
            }
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

        /* Not used constand (this const are directly inlined in process block method) */

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
