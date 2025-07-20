using Arctium.Shared.Helpers.Binary;
using System;
using System.Runtime.CompilerServices;
using static Arctium.Shared.Helpers.Binary.BinConverter;

namespace Arctium.Cryptography.Ciphers.StreamCiphers
{
    // a == constrant words
    // x == state
    // c == counter system


    public unsafe class Rabbit : StreamCipherBase
    {
        /// <summary>
        /// Length in bytes of Rabbit keystream block 
        /// </summary>
        const int OutpuKeystreamLength = 16;

        private readonly uint[] CounterAContants = new uint[]
        {
            0x4D34D34D,
            0xD34D34D3,
            0x34D34D34,
            0x4D34D34D,
            0xD34D34D3,
            0x34D34D34,
            0x4D34D34D,
            0xD34D34D3
        };

        

        // generated keystream block may not be used 
        // entirely on encryption. This fileds holds unused bytes 
        // for encryption 
        byte[] existingKeystream;
        int toUtilizeBytesCount;
        uint counterCarryBit;
        uint[] xState;
        uint[] cState;
        private byte[] iv;

        /// <summary>
        /// This constructor should not be used. Ctor with IV is recommended. <br/>
        /// Creates <see cref="Rabbit"/> instance without initialization vector.
        /// </summary>
        /// <param name="key">16-byte key for the rabbit algorithm</param>
        public Rabbit(byte[] key) : this(key, null)
        {
            
        }

        public Rabbit(byte[] key, byte[] iv) : base(key)
        {
            if (key == null) throw new ArgumentNullException("key");
            if (key.Length != 16) throw new ArgumentException("Length of the key must be 16 bytes");

            if (iv != null)
            {
                if (iv.Length != 8) throw new ArgumentException("Length of the IV must be 8 bytes");
            }

            this.xState = new uint[8];
            this.cState = new uint[8];
            this.iv = iv;
            Reset();
        }

        public void Reset()
        {
            counterCarryBit = 0;
            this.toUtilizeBytesCount = 0;
            if (existingKeystream == null) existingKeystream = new byte[16];

            uint* x = stackalloc uint[8];
            uint* c = stackalloc uint[8];
            uint* a = stackalloc uint[8];
            uint carryBit = 0;
            uint* carryBitPtr = &carryBit;

            CopyStateToUsafe(a, x, c, carryBitPtr);
            KeySetupScheme(key, x, c, a, carryBitPtr);
            CopyStateToSafe(x, c, carryBitPtr);
        }

        public override long Decrypt(byte[] inputBuffer, long inputOffset, byte[] outputBuffer, long outputOffset, long length)
        {
            return ExecuteTransformOnInput(inputBuffer, inputOffset, length, outputBuffer, outputOffset);
        }

        public override long Encrypt(byte[] inputBuffer, long inputOffset, byte[] outputBuffer, long outputOffset, long length)
        {
            return ExecuteTransformOnInput(inputBuffer, inputOffset, length, outputBuffer, outputOffset);
        }

        private long ExecuteTransformOnInput(byte[] inputBuffer, long inputOffset, long length, byte[] outputBuffer, long outputOffset)
        {
            if (length == 0) return 0;
            if (length < 0) throw new ArgumentException("Length of the input buffer cannot be negative", "length");

            // if keystream is already generated
            long utilizedLength = UtilizeExistingKeyStream(inputBuffer, inputOffset, length, outputBuffer, outputOffset);
            if (utilizedLength == length) return utilizedLength;

            long remainingBytes = length - utilizedLength;
            long remaining16ByteBlocks = remainingBytes / 16;

            uint cbit = 0;
            uint* a = stackalloc uint[8]; // constant words
            uint* x = stackalloc uint[8]; // state
            uint* c = stackalloc uint[8]; // counter 
            byte* s = stackalloc byte[16]; // keystream
            uint* carryBit = &cbit;
            CopyStateToUsafe(a, x, c, carryBit);

            NextStateFunction(x, a, c, carryBit);
            ExtractKeystream(x, s);

            if (remaining16ByteBlocks > 0)
            {
                fixed (byte* inPtr = &inputBuffer[0], outPtr = &outputBuffer[0])
                {
                    ulong* inp = (ulong*)inPtr, outp = (ulong*)outPtr;
                    ulong* sp = (ulong*)s; // keystream

                    for (long i = 0; i < remaining16ByteBlocks; i++)
                    {
                        outp[0] = inp[0] ^ sp[0];
                        outp[1] = inp[1] ^ sp[1];

                        inp += 2;
                        outp += 2;

                        NextStateFunction(x, a, c, carryBit);
                        ExtractKeystream(x, s);
                    }
                }

                remainingBytes -= remaining16ByteBlocks * 16;
            }

            toUtilizeBytesCount = 16;
            for (int i = 0; i < 16; i++) existingKeystream[i] = s[i];

            // if input length is not a multiply of 128-but block
            // this remaining bytes must be processed on existing keystream,
            // and this keystream is cached for future call of this method
            if (remainingBytes > 0)
            {
                long restBytesOffset = length - remainingBytes;

                remainingBytes -= UtilizeExistingKeyStream(
                    inputBuffer, 
                    inputOffset + restBytesOffset, 
                    remainingBytes, 
                    outputBuffer, 
                    outputOffset + restBytesOffset);
            }

            return length - remainingBytes;
        }

        private static void ExtractKeystream(uint* x, byte* s)
        {
            ushort* keyStream = stackalloc ushort[8];

            keyStream[7] = (ushort)(x[0] ^ (x[5] >> 16));
            keyStream[6] = (ushort)((x[0] >> 16) ^ x[3]);
            keyStream[5] = (ushort)(x[2] ^ (x[7]>>16));
            keyStream[4] = (ushort)((x[2] >> 16) ^ x[5]);
            keyStream[3] = (ushort)(x[4] ^ (x[1] >> 16));
            keyStream[2] = (ushort)((x[4] >> 16) ^ x[7]);
            keyStream[1] = (ushort)(x[6] ^ (x[3] >> 16));
            keyStream[0] = (ushort)((x[6] >> 16) ^ x[1]);

            for (int i = 0; i < 8; i++)
            {
                // write as bigendian
                s[(i * 2)] = (byte)(keyStream[i] >> 8);
                s[(i * 2) + 1] = (byte)(keyStream[i]);
            }
        }

        /// <summary>
        /// If input block do not match exactly  length
        /// of generated keystream, cached keystream is used by this functinon
        /// to encryptions
        /// </summary>
        private long UtilizeExistingKeyStream(byte[] inputBuffer, long inputOffset, long length, byte[] outputBuffer, long outputOffset)
        {
            if (toUtilizeBytesCount < 1) return 0;

            long utilizeLength = length > toUtilizeBytesCount ? toUtilizeBytesCount : length;

            int startIndex = 16 - toUtilizeBytesCount;

            for (int i = 0; i < utilizeLength; i++, outputOffset++, inputOffset++)
            {
                outputBuffer[outputOffset] = (byte)(inputBuffer[inputOffset] ^ existingKeystream[startIndex + i]);
            }

            toUtilizeBytesCount -= (int)utilizeLength;
            return utilizeLength;
        }

        private void KeySetupScheme(byte[] key, uint* outx, uint* outc, uint* a, uint* carryBit)
        {
            ushort[] k = new ushort[8];
            for (int i = 0; i < 8; i++)
            {
                k[7 - i] = BinConverter.ToUShortBE(key, i * 2);
            }

            outx[0] = (uint)((k[1] << 16) | k[0]);
            outx[2] = (uint)((k[3] << 16) | k[2]);
            outx[4] = (uint)((k[5] << 16) | k[4]);
            outx[6] = (uint)((k[7] << 16) | k[6]);

            outx[1] = (uint)((k[6] << 16) | k[5]);
            outx[3] = (uint)((k[0] << 16) | k[7]);
            outx[5] = (uint)((k[2] << 16) | k[1]);
            outx[7] = (uint)((k[4] << 16) | k[3]);

            // counters

            outc[0] = (uint)((k[4] << 16) | k[5]);
            outc[2] = (uint)((k[6] << 16) | k[7]);
            outc[4] = (uint)((k[0] << 16) | k[1]);
            outc[6] = (uint)((k[2] << 16) | k[3]);

            outc[1] = (uint)((k[1] << 16) | k[2]);
            outc[3] = (uint)((k[3] << 16) | k[4]);
            outc[5] = (uint)((k[5] << 16) | k[6]);
            outc[7] = (uint)((k[7] << 16) | k[0]);

            // state

            NextStateFunction(outx, a, outc, carryBit);
            NextStateFunction(outx, a, outc, carryBit);
            NextStateFunction(outx, a, outc, carryBit);
            NextStateFunction(outx, a, outc, carryBit);


            // reinitializing counters

            for (int i = 0; i < 8; i++)
            {
                outc[i] = outc[i] ^ (outx[(i + 4) % 8]);
            }

            // IV setup scheme

            if (iv != null)
            {
                outc[0] ^= ToUIntBE(iv, 4);
                outc[2] ^= ToUIntBE(iv, 0);
                outc[4] ^= ToUIntBE(iv, 4);
                outc[6] ^= ToUIntBE(iv, 0);

                outc[1] ^= (uint)((ToUShortBE(iv, 0) << 16)  | (ToUShortBE(iv, 4)));
                outc[3] ^= (uint)((ToUShortBE(iv, 2) << 16) | (ToUShortBE(iv, 6)));
                outc[5] ^= (uint)((ToUShortBE(iv, 0) << 16)  | (ToUShortBE(iv, 4)));
                outc[7] ^= (uint)((ToUShortBE(iv, 2) << 16) | (ToUShortBE(iv, 6)));

                NextStateFunction(outx, a, outc, carryBit);
                NextStateFunction(outx, a, outc, carryBit);
                NextStateFunction(outx, a, outc, carryBit);
                NextStateFunction(outx, a, outc, carryBit);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void NextStateFunction(uint* x, uint* a, uint* c, uint* carryBit)
        {
            CounterSystem(c, a, carryBit);

            uint g0 = G(x[0], c[0]);
            uint g1 = G(x[1], c[1]);
            uint g2 = G(x[2], c[2]);
            uint g3 = G(x[3], c[3]);
            uint g4 = G(x[4], c[4]);
            uint g5 = G(x[5], c[5]);
            uint g6 = G(x[6], c[6]);
            uint g7 = G(x[7], c[7]);

            x[0] = g0 + ROTL(g7, 16) + ROTL(g6, 16);
            x[1] = g1 + ROTL(g0, 8) + g7;
            x[2] = g2 + ROTL(g1, 16) + ROTL(g0, 16);
            x[3] = g3 + ROTL(g2, 8) + g1;
            x[4] = g4 + ROTL(g3, 16) + ROTL(g2, 16);
            x[5] = g5 + ROTL(g4, 8) + g3;
            x[6] = g6 + ROTL(g5, 16) + ROTL(g4, 16);
            x[7] = g7 + ROTL(g6, 8) + g5;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint G(uint x, uint c)
        {
            // (x + c) must be mod 2^32

            uint add = (x + c);
            ulong addLong = add;
            ulong square = addLong * addLong;
            ulong xored = square ^ (square >> 32);
            return (uint)(xored);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void CounterSystem(uint* c, uint* a, uint* carryBit)
        {
            ulong result = 0;

            for (int i = 0; i < 8; i++)
            {
                result = (ulong)c[i] + a[i] + *carryBit;
                *carryBit = (uint)(result >> 32);
                c[i] = (uint)result;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void CopyStateToUsafe(uint* a, uint* x, uint* c, uint* carryBit)
        {
            a[0] = this.CounterAContants[0];
            a[1] = this.CounterAContants[1];
            a[2] = this.CounterAContants[2];
            a[3] = this.CounterAContants[3];
            a[4] = this.CounterAContants[4];
            a[5] = this.CounterAContants[5];
            a[6] = this.CounterAContants[6];
            a[7] = this.CounterAContants[7];

            x[0] = this.xState[0];
            x[1] = this.xState[1];
            x[2] = this.xState[2];
            x[3] = this.xState[3];
            x[4] = this.xState[4];
            x[5] = this.xState[5];
            x[6] = this.xState[6];
            x[7] = this.xState[7];

            c[0] = this.cState[0];
            c[1] = this.cState[1];
            c[2] = this.cState[2];
            c[3] = this.cState[3];
            c[4] = this.cState[4];
            c[5] = this.cState[5];
            c[6] = this.cState[6];
            c[7] = this.cState[7];

            *carryBit = this.counterCarryBit;
        }


        /// <summary>
        /// Copy unsafe state of the cipher to 
        /// class fields to preserve to next cipher iteration
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void CopyStateToSafe(uint* x, uint* c, uint* carryBit)
        {
            this.counterCarryBit = *carryBit;

            this.xState[0] = x[0];
            this.xState[1] = x[1];
            this.xState[2] = x[2];
            this.xState[3] = x[3];
            this.xState[4] = x[4];
            this.xState[5] = x[5];
            this.xState[6] = x[6];
            this.xState[7] = x[7];

            this.cState[0] = c[0];
            this.cState[1] = c[1];
            this.cState[2] = c[2];
            this.cState[3] = c[3];
            this.cState[4] = c[4];
            this.cState[5] = c[5];
            this.cState[6] = c[6];
            this.cState[7] = c[7];
        }

        private static uint ROTL(uint v, int r)
        {
            return (v << r) | (v >> (32 - r));
        }
    }
}

/* [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint G(ulong x, ulong c)
        {
            ulong square = ((ulong)((uint)(x + c))) * (ulong)((uint)(x + c));
            ulong shifted = (square >> 32);
            uint xored = (uint)square ^ (uint)shifted;
            return (uint)(xored);
        }*/
