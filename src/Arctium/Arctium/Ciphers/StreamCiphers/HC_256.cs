using Arctium.Cryptography.Ciphers.StreamCiphers.Helpers;
using Arctium.Shared;
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

        /// <summary>
        /// </summary>
        /// <param name="key">Key is a 8 uint values in big-endian</param>
        /// <param name="iv">In 8 uint in big-endian</param>
        public HC_256(byte[] key, byte[] iv) : base(key)
        {
            if (iv == null) throw new ArgumentNullException("iv");
            if (key.Length != 32) throw new ArgumentException("Key must have 256-bits");
            if (iv.Length != 32) throw new ArgumentException("IV must have 256-bits");

            keyCache = new CachedKey(64);

            P = new uint[1024];
            Q = new uint[1024];

            this.iv = iv;
            Initialize();
        }

        public override long Decrypt(byte[] inputBuffer, long inputOffset, byte[] outputBuffer, long outputOffset, long length)
        {
            TransformInput(inputBuffer, inputOffset, length, outputBuffer, outputOffset);
            return length;
        }

        /// <summary>
        /// Try to encryptl large chunks of data instead of calling this method sevelar times. <br/>
        /// Expected 64 bytes input buffer (length is multiply of 64)
        /// </summary>
        public override long Encrypt(byte[] inputBuffer, long inputOffset, byte[] outputBuffer, long outputOffset, long length)
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

            long blockSizeInBytes = 64;
            long remainingBytes = length - utilized;
            long remainingBlocks = (remainingBytes / blockSizeInBytes);

            // bytes to int count
            uint* generatedKeystream = stackalloc uint[16];

            ulong counter = totalCounter;

            fixed (uint* p = &P[0], q = &Q[0])
            {
                if (remainingBlocks > 0)
                {
                    fixed (byte* inputPtr = &input[0], outputPtr = &output[0])
                    {
                        byte* currentInputPtr = inputPtr;
                        byte* currentOutputPtr = outputPtr;

                        for (long i = 0; i < remainingBlocks; i++)
                        {
                            Generate64BytesKeystream(p, q, generatedKeystream, &counter);
                            Xor64BytesKeystream(generatedKeystream, inputPtr, outputPtr);

                            currentInputPtr += 64;
                            currentOutputPtr += 64;
                        }
                    }
                }

                remainingBytes -= (remainingBlocks * blockSizeInBytes);

                if (remainingBytes > 0)
                {
                    long offset = length - remainingBytes;

                    Generate64BytesKeystream(p, q, generatedKeystream, &counter);
                    keyCache.RefreshKey(MemMap.ToByteArrayBE(generatedKeystream, 16));
                    keyCache.UtilizeExitingKeyXor(input, inputOffset + offset, remainingBytes, output, outputOffset + offset);
                }
            }

            totalCounter = counter;
        }


        /// <summary>
        /// Xors 16 uint of keystream with 64 bytes of input and writes to outputs
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Xor64BytesKeystream(uint* keystream, byte* input, byte* output)
        {
            output[0] = (byte)(input[0] ^ (keystream[0] >> 24));
            output[1] = (byte)(input[1] ^ (keystream[0] >> 16));
            output[2] = (byte)(input[2] ^ (keystream[0] >> 8));
            output[3] = (byte)(input[3] ^ (keystream[0] >> 0));
            output[4] = (byte)(input[4] ^ (keystream[1] >> 24));
            output[5] = (byte)(input[5] ^ (keystream[1] >> 16));
            output[6] = (byte)(input[6] ^ (keystream[1] >> 8));
            output[7] = (byte)(input[7] ^ (keystream[1] >> 0));
            output[8] = (byte)(input[8] ^ (keystream[2] >> 24));
            output[9] = (byte)(input[9] ^ (keystream[2] >> 16));
            output[10] = (byte)(input[10] ^ (keystream[2] >> 8));
            output[11] = (byte)(input[11] ^ (keystream[2] >> 0));
            output[12] = (byte)(input[12] ^ (keystream[3] >> 24));
            output[13] = (byte)(input[13] ^ (keystream[3] >> 16));
            output[14] = (byte)(input[14] ^ (keystream[3] >> 8));
            output[15] = (byte)(input[15] ^ (keystream[3] >> 0));
            output[16] = (byte)(input[16] ^ (keystream[4] >> 24));
            output[17] = (byte)(input[17] ^ (keystream[4] >> 16));
            output[18] = (byte)(input[18] ^ (keystream[4] >> 8));
            output[19] = (byte)(input[19] ^ (keystream[4] >> 0));
            output[20] = (byte)(input[20] ^ (keystream[5] >> 24));
            output[21] = (byte)(input[21] ^ (keystream[5] >> 16));
            output[22] = (byte)(input[22] ^ (keystream[5] >> 8));
            output[23] = (byte)(input[23] ^ (keystream[5] >> 0));
            output[24] = (byte)(input[24] ^ (keystream[6] >> 24));
            output[25] = (byte)(input[25] ^ (keystream[6] >> 16));
            output[26] = (byte)(input[26] ^ (keystream[6] >> 8));
            output[27] = (byte)(input[27] ^ (keystream[6] >> 0));
            output[28] = (byte)(input[28] ^ (keystream[7] >> 24));
            output[29] = (byte)(input[29] ^ (keystream[7] >> 16));
            output[30] = (byte)(input[30] ^ (keystream[7] >> 8));
            output[31] = (byte)(input[31] ^ (keystream[7] >> 0));
            output[32] = (byte)(input[32] ^ (keystream[8] >> 24));
            output[33] = (byte)(input[33] ^ (keystream[8] >> 16));
            output[34] = (byte)(input[34] ^ (keystream[8] >> 8));
            output[35] = (byte)(input[35] ^ (keystream[8] >> 0));
            output[36] = (byte)(input[36] ^ (keystream[9] >> 24));
            output[37] = (byte)(input[37] ^ (keystream[9] >> 16));
            output[38] = (byte)(input[38] ^ (keystream[9] >> 8));
            output[39] = (byte)(input[39] ^ (keystream[9] >> 0));
            output[40] = (byte)(input[40] ^ (keystream[10] >> 24));
            output[41] = (byte)(input[41] ^ (keystream[10] >> 16));
            output[42] = (byte)(input[42] ^ (keystream[10] >> 8));
            output[43] = (byte)(input[43] ^ (keystream[10] >> 0));
            output[44] = (byte)(input[44] ^ (keystream[11] >> 24));
            output[45] = (byte)(input[45] ^ (keystream[11] >> 16));
            output[46] = (byte)(input[46] ^ (keystream[11] >> 8));
            output[47] = (byte)(input[47] ^ (keystream[11] >> 0));
            output[48] = (byte)(input[48] ^ (keystream[12] >> 24));
            output[49] = (byte)(input[49] ^ (keystream[12] >> 16));
            output[50] = (byte)(input[50] ^ (keystream[12] >> 8));
            output[51] = (byte)(input[51] ^ (keystream[12] >> 0));
            output[52] = (byte)(input[52] ^ (keystream[13] >> 24));
            output[53] = (byte)(input[53] ^ (keystream[13] >> 16));
            output[54] = (byte)(input[54] ^ (keystream[13] >> 8));
            output[55] = (byte)(input[55] ^ (keystream[13] >> 0));
            output[56] = (byte)(input[56] ^ (keystream[14] >> 24));
            output[57] = (byte)(input[57] ^ (keystream[14] >> 16));
            output[58] = (byte)(input[58] ^ (keystream[14] >> 8));
            output[59] = (byte)(input[59] ^ (keystream[14] >> 0));
            output[60] = (byte)(input[60] ^ (keystream[15] >> 24));
            output[61] = (byte)(input[61] ^ (keystream[15] >> 16));
            output[62] = (byte)(input[62] ^ (keystream[15] >> 8));
            output[63] = (byte)(input[63] ^ (keystream[15] >> 0));
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
