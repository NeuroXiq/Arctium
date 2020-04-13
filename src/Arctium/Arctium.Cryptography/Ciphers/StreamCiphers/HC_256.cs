using Arctium.Cryptography.Ciphers.StreamCiphers.Helpers;
using Arctium.Shared.Helpers.Binary;
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;

/*
 * Implementation of the HC-256 stream cipher, ESTREAM Project
 * 
 * Invented by Hongjun Wu, 
 * Institute for Infocomm Research, Singaporehongjun@i2r.a-star.edu.sg
 */

namespace Arctium.Cryptography.Ciphers.StreamCiphers
{
    /// <summary>
    /// HC-256 stream cipher created by Hongjun Wu, ESTREAM project
    /// </summary>
    public unsafe class HC_256 : StreamCipherBase
    {
        // 0x3ff == 1024 - 1 (binary mask)
        const uint Mod1024 = 0x3FF;
        const uint Mod2048 = 0x7FF;
        const int GeneratedKeystreamLength = 64;

        uint[] P;
        uint[] Q;
        byte[] iv;
        
        // if bytes not utilized, 
        byte[] cachedKeystream;
        byte[] cachedKeystreamLength;

        // total amount of generater uint of keystream.
        // this coutner do not include initialization setup.
        // is updated AFTER initialization 
        ulong totalCounter;

        CachedKey keyCache;

        public HC_256(byte[] key, byte[] iv) : base(key)
        {
            if (iv == null) throw new ArgumentNullException("iv");
            if (key.Length != 32) throw new ArgumentException("Key must have 256-bits");
            if (iv.Length != 32) throw new ArgumentException("IV must have 256-bits");

            keyCache = new CachedKey(32);

            P = new uint[1024];
            Q = new uint[1024];

            this.iv = iv;
            Initialize();
        }

        public override long Decrypt(byte[] inputBuffer, long inputOffset, long length, byte[] outputBuffer, long outputOffset)
        {
            TransformInput(inputBuffer, inputOffset, length, outputBuffer, outputOffset);
            return length;
        }

        public override long Encrypt(byte[] inputBuffer, long inputOffset, long length, byte[] outputBuffer, long outputOffset)
        {
            TransformInput(inputBuffer, inputOffset, length, outputBuffer, outputOffset);
            return length;
        }

        public void Initialize()
        {
            totalCounter = 0;

            for (int i = 0; i < 8; i++)
            {
                P[i] = BinConverter.ToUIntBE(key, i * 4);
                P[i + 8] = BinConverter.ToUIntBE(iv, i * 4);
            }

            fixed (uint* pPtr = &P[0], qPtr = &Q[0])
            {
                uint* p = pPtr, q = qPtr;

                // 

                for (uint i = 16; i < (512 + 16); i++)
                    p[i] = F2(p[i - 2]) + p[i - 7] + F1(p[i - 15]) + p[i - 16] + i;

                // copy that data can be referenced from start position ('p[i-16]')

                for (uint i = 0; i < 16; i++)
                {
                    p[i] = p[512 + i];
                }

                for (uint i = 16; i < 1024; i++)
                    p[i] = F2(p[i - 2]) + p[i - 7] + F1(p[i - 15]) + p[i - 16] + (i + 512);

                // Q Table

                for (uint i = 0; i < 16; i++)
                    q[i] = p[1024 - 16 + i];

                for (uint i = 16; i < 32; i++ )
                    q[i] = F2(q[i - 2]) + q[i- 7] + F1(q[i- 15]) + q[i- 16] + (1520 + i);

                for (uint i = 0; i < 16; i++)
                    q[i] = q[i + 16];

                for (uint i = 16; i < 1024; i++)
                    q[i] = F2(q[i - 2]) + q[i - 7] + F1(q[i - 15]) + q[i - 16] + (1536 + i);

                uint* ignoreKeystream = stackalloc uint[64];
                ulong ignoreCounter = 0;

                for (ulong i = 0; i < 256; i++)
                {
                    Generate64BytesKeystream(p, q, ignoreKeystream, &ignoreCounter);
                }
            }
        }


        void TransformInput(byte[] input, long inputOffset, long length, byte[] output, long outputOffset)
        {
            long utilized = keyCache.UtilizeExitingKeyXor(input, inputOffset, length, output, outputOffset);
            if (utilized == length) return;

            long remainingBytes = length - utilized;
            long remainingBlocks = (remainingBytes / GeneratedKeystreamLength);

            // bytes to int count
            uint* generatedKeystream = stackalloc uint[GeneratedKeystreamLength / 4];

            ulong counter = totalCounter;

            fixed (uint* p = &P[0], q = &Q[0])
            {
                Generate64BytesKeystream(p, q, generatedKeystream, &counter);

                if (remainingBlocks > 0)
                {
                    fixed (byte* inPtr = &input[0], outPtr = &output[0])
                    {
                        uint* ip = (uint*)inPtr;
                        uint* op = (uint*)outPtr;

                        for (long i = 0; i < remainingBlocks; i++)
                        {
                            for (int j = 0; j < 16; j++)
                            {
                                op[j] = ip[j] ^ generatedKeystream[j];
                            }

                            op += GeneratedKeystreamLength / 16;
                            ip += GeneratedKeystreamLength / 16;

                            Generate64BytesKeystream(p, q, generatedKeystream, &counter);
                        }
                    }
                }
            }
        }


        //
        // generates 64 bytes of the keysteam
        //

        static void Generate64BytesKeystream(uint* p, uint* q, uint* outputKeystream, ulong* counter2048)
        {
            uint j = (uint)(*counter2048 % 1024);

            if ((*counter2048 % 2048) < 1024)
            {
                Generate32BitsKeystream(p, q, outputKeystream + 0, j + 0);
                Generate32BitsKeystream(p, q, outputKeystream + 1, j + 1);
                Generate32BitsKeystream(p, q, outputKeystream + 2, j + 2);
                Generate32BitsKeystream(p, q, outputKeystream + 3, j + 3);
                Generate32BitsKeystream(p, q, outputKeystream + 4, j + 4);
                Generate32BitsKeystream(p, q, outputKeystream + 5, j + 5);
                Generate32BitsKeystream(p, q, outputKeystream + 6, j + 6);
                Generate32BitsKeystream(p, q, outputKeystream + 7, j + 7);
                Generate32BitsKeystream(p, q, outputKeystream + 8, j + 8);
                Generate32BitsKeystream(p, q, outputKeystream + 9, j + 9);
                Generate32BitsKeystream(p, q, outputKeystream + 10, j + 10);
                Generate32BitsKeystream(p, q, outputKeystream + 11, j + 11);
                Generate32BitsKeystream(p, q, outputKeystream + 12, j + 12);
                Generate32BitsKeystream(p, q, outputKeystream + 13, j + 13);
                Generate32BitsKeystream(p, q, outputKeystream + 14, j + 14);
                Generate32BitsKeystream(p, q, outputKeystream + 15, j + 15);
            }
            else
            {
                Generate32BitsKeystream(q, p, outputKeystream + 0, j + 0);
                Generate32BitsKeystream(q, p, outputKeystream + 1, j + 1);
                Generate32BitsKeystream(q, p, outputKeystream + 2, j + 2);
                Generate32BitsKeystream(q, p, outputKeystream + 3, j + 3);
                Generate32BitsKeystream(q, p, outputKeystream + 4, j + 4);
                Generate32BitsKeystream(q, p, outputKeystream + 5, j + 5);
                Generate32BitsKeystream(q, p, outputKeystream + 6, j + 6);
                Generate32BitsKeystream(q, p, outputKeystream + 7, j + 7);
                Generate32BitsKeystream(q, p, outputKeystream + 8, j + 8);
                Generate32BitsKeystream(q, p, outputKeystream + 9, j + 9);
                Generate32BitsKeystream(q, p, outputKeystream + 10, j + 10);
                Generate32BitsKeystream(q, p, outputKeystream + 11, j + 11);
                Generate32BitsKeystream(q, p, outputKeystream + 12, j + 12);
                Generate32BitsKeystream(q, p, outputKeystream + 13, j + 13);
                Generate32BitsKeystream(q, p, outputKeystream + 14, j + 14);
                Generate32BitsKeystream(q, p, outputKeystream + 15, j + 15);
            }

            *counter2048 += 16;
        }


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        static void Generate32BitsKeystream(uint* p, uint* q, uint* outputKeystream, uint counter1024)
        {
            uint j0 = counter1024;
            uint j1 = (j0 - 10) & Mod1024;
            uint j2 = (j0 - 3) & Mod1024;
            uint j3 = (j0 - 1023) & Mod1024;

            p[j0] = p[j0] + p[j1] + G1(p[j2], p[j3], q);
            *outputKeystream = H1(p[(j0 - 12) & Mod1024], q) ^ (p[j0]);
        }

        #region HS-256 Functions

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        static uint F1(uint x) { return ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3); }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        static uint F2(uint x) { return ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10); }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        static uint G1(uint x, uint y, uint* q) { return (ROTR(x, 10) ^ ROTR(y, 23)) + q[(x ^ y) & Mod1024]; }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        static uint G2(uint x, uint y, uint* p) { return (ROTR(x, 10) ^ ROTR(y, 23)) + p[(x ^ y) & Mod1024]; }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        static uint H1(uint x, uint* q)
        {
            uint x0 = (x & 0xFF) >> 0;
            uint x1 = (x & 0xFF00) >> 8;
            uint x2 = (x & 0xFF0000) >> 16;
            uint x3 = (x & 0xFF000000) >> 24;

            return q[x0] + q[x1 + 256] + q[x2 + 512] + q[x3 + 768];
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        static uint H2(uint x, uint* p)
        {
            uint x0 = (x & 0xFF) >> 0;
            uint x1 = (x & 0xFF00) >> 8;
            uint x2 = (x & 0xFF0000) >> 16;
            uint x3 = (x & 0xFF000000) >> 24;

            return p[x0] + p[x1 + 256] + p[x2 + 512] + p[x3 + 768];
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        static uint ROTR(uint x, int rotate) { return (x >> rotate) | (x << (32 - rotate)); }
        #endregion
    }
}
