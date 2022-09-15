using Arctium.Shared.Helpers.Binary;
using Arctium.Shared.Helpers.Buffers;
using System;
using System.Collections.Generic;

namespace Arctium.Cryptography.Ciphers.BlockCiphers.ModeOfOperation
{
    /// <summary>
    /// The CCM Mode for
    /// Authentication and
    /// Confidentiality
    /// </summary>
    public static class CCMModeAlgorithm
    {
        static readonly int[] ValidT = new int[] { 4, 6, 8, 10, 12, 14, 16 };
        static readonly int[] ValidQ = new int[] { 2, 3, 4, 5, 6, 7, 8 };
        static readonly int[] ValidN = new int[] { 7, 8, 9, 10, 11, 12, 13 };


        public class Context
        {
            public BlockCipher Cipher;
            public byte[] Key;

        }

        public static Context Init(byte[] key)
        {
            var context = new Context();
            context.Key = key;
            // Reset(context, key);

            return context;
        }

        static void ValidateParams(int t, int q, int n)
        {
            bool tValid = false, nValid = false, qValid = false;

            for (int i = 0; i < ValidT.Length; i++) tValid |= ValidT[i] == t;
            for (int i = 0; i < ValidQ.Length; i++) qValid |= ValidQ[i] == q;
            for (int i = 0; i < ValidN.Length; i++) nValid |= ValidN[i] == n;

            if (n + q != 15) throw new Exception("internal: invalid n+q != 15");
            if (!(tValid && nValid && qValid)) throw new Exception("internal tvalid, nvalid, qvalid");
        }

        public static void GenerationEncryption(Context context,
            byte[] nonce,
            long nonceOffset,
            long nonceLength,
            byte[] payload,
            long payloadOffset,
            long payloadLength,
            byte[] associatedData,
            long associatedDataOffset,
            long associatedDataLengt,
            byte[] output,
            int outputOffset,
            int t)
        {
            ByteBuf buf = new ByteBuf();

            byte[] T = new byte[16];
            ComputeT(context, nonce, nonceOffset, nonceLength,
                payload, payloadOffset, payloadLength,
                associatedData, associatedDataOffset, associatedDataLengt, t, T);

            AES aes = new AES(context.Key);

            byte[] ctr = new byte[16];
            byte[] ctrEnc = new byte[16];

            int q = 15 - nonce.Length;

            ctr[0] = (byte)(q - 1);
            Array.Copy(nonce, 0, ctr, 1, nonce.Length);

            long pd = payloadOffset;
            long outOffs = outputOffset;
            int ctri = 0;


            // how much possible full 16-bytes block of payload
            for (; pd <= payloadLength - 16 + payloadOffset; pd += 16, outOffs += 16)
            {
                ctri++;
                ToBytesBE(ctri, q, ctr, 16 - q);
                aes.Encrypt(ctr, 0, ctrEnc, 0, 16);
                Xor(payload, pd, ctrEnc, 0, output, outOffs);
            }

            buf.ClearZero(16);

            long remLen = (payloadOffset + payloadLength - pd);

            // if remaining (payloadLength % 16 != 0) then process remaining
            if (remLen > 0)
            {
                ctri++;
                
                for (; pd < payloadLength + payloadOffset; pd++) buf.Append(payload[pd]);

                ToBytesBE(ctri, q, ctr, 16 - q);
                aes.Encrypt(ctr, 0, ctrEnc, 0, 16);

                Xor(buf.Buffer, 0, ctrEnc, 0, output, outOffs, (int)remLen);
                outOffs += remLen;
            }

            ToBytesBE(0, q, ctr, 16 - q);
            aes.Encrypt(ctr, 0, ctrEnc, 0, 16);

            // compute final T value (MAC) by xor 'T' with (counter '0')
            for (int j = 0; j < t; j++, outOffs++)
            {
                T[j] ^= ctrEnc[j];
                output[outOffs] = T[j]; 
            }
        }

        static void ComputeT(Context context, byte[] nonce,
            long nonceOffset,
            long nonceLength,
            byte[] payload,
            long payloadOffset,
            long payloadLength,
            byte[] associatedData,
            long associatedDataOffset,
            long associatedDataLength,
            int t,
            byte[] output)
        {
            ByteBuf buf = new ByteBuf();

            long p = payload.Length;
            int q = 15 - nonce.Length;
            int n = nonce.Length;

            ValidateParams(t, q, n);


            byte[] firstBlock = new byte[16];

            byte b0 = 0;

            /* first 16 bytes */

            if (associatedData.Length > 0) b0 |= (1 << 6);
            b0 |= (byte)(((t - 2) / 2) << 3);
            b0 |= (byte)(q - 1);

            firstBlock[0] = b0;
            MemCpy.Copy(nonce, nonceOffset, firstBlock, 1, nonceLength);


            ToBytesBE(p, q, firstBlock, 16 - q);

            /* end / first 16 bytes */

            long a = associatedData.Length;
            int slen = 0;

            if ((a > 0) && (65280 > a))
            {
                buf.Append((byte)(a >> 8));
                buf.Append((byte)(a >> 0));
            }
            else if ((65280 <= a) && (a < 0xffffffff))
            {
                buf.Append(0xff);
                buf.Append(0xfe);
                buf.AppendFromOutside(4);

                ToBytes1UIntBE((uint)a, buf.Buffer, buf.Length - 4);
            }
            else if ((a >= 0xFFFFFFFF))
            {
                buf.Append(0xff);
                buf.Append(0xff);
                buf.AppendFromOutside(8);

                ToBytes1ULongBE((ulong)a, buf.Buffer, buf.Length - 8);
            }

            long ad = associatedDataOffset;
            long pd = payloadOffset;

            if (associatedDataLength > 0)
            {
                for (; (buf.Length < 16) && ad < associatedDataLength; ad++) buf.Append(associatedData[ad]);
                for (int i = 0; buf.Length < 16; i++) buf.Append(0);
            }

            AES aes = new AES(context.Key);
            byte[] yi_prev = new byte[16];
            byte[] yi_next = new byte[16];

            aes.Encrypt(firstBlock, 0, yi_next, 0, 16);

            if (buf.Length > 0)
            {
                Xor(yi_next, 0, buf.Buffer, 0, yi_prev, 0);
                aes.Encrypt(yi_prev, 0, yi_next, 0, 16);
            }

            for (; ad <= associatedData.Length - 16; ad += 16)
            {
                Xor(yi_next, 0, associatedData, ad, yi_prev, 0);
                aes.Encrypt(yi_prev, 0, yi_next, 0, 16);
            }

            buf.ClearZero(16);
            if (ad < associatedDataLength)
            {
                for (; ad < associatedData.Length; ad++) buf.Append(associatedData[ad]);
                while (buf.Length < 16) buf.Append(0);

                Xor(yi_next, 0, buf.Buffer, 0, yi_prev, 0);
                aes.Encrypt(yi_prev, 0, yi_next, 0, 16);
            }

            // xor payload full blocks how much possible

            for (; pd <= payloadLength - 16; pd += 16)
            {
                Xor(yi_next, 0, payload, pd, yi_prev, 0);
                aes.Encrypt(yi_prev, 0, yi_next, 0, 16);
            }

            if (pd < payloadLength)
            {
                // remaining payload not fit in 16 blocks

                buf.ClearZero(16);
                for (; pd < payload.Length; pd++) buf.Append(payload[pd]);

                Xor(yi_next, 0, buf.Buffer, 0, yi_prev, 0);
                aes.Encrypt(yi_prev, 0, yi_next, 0, 16);
            }

            Array.Copy(yi_next, 0, output, 0, 16);
        }

        static void Xor(byte[] src, long srcOff, byte[] with, long wof,  byte[] dest, long destOffs, int len = 16)
        {
            for (int i = 0; i < len; i++) dest[i + destOffs] = (byte)(src[i + srcOff] ^ with[i + wof]);
        }

        class ByteBuf
        {
            public byte[] Buffer;
            public long Length;

            public ByteBuf()
            {
                Buffer = new byte[16];
            }

            public void ClearZero(int len)
            {
                for (int i = 0; i < len; i++) Buffer[i] = 0;
                Length = 0;
            }

            public void Append(byte v)
            {
                Extend(1);
                Buffer[Length] = v;
                Length++;
            }

            public void AppendFromOutside(int length)
            {
                Extend(4);
                Length += 4;
            }

            public void Extend(long length)
            {
                if (Buffer.Length < length + Length)
                {
                    byte[] temp = new byte[length + Buffer.Length];
                    Array.Copy(Buffer, 0, temp, 0, Length);
                    Buffer = temp;
                }
            }

            public void Append(byte[] buffer, long offset, long length)
            {
                Extend(length);
                Array.Copy(buffer, offset, Buffer, Length, length);
                Length += length;
            }
        }

        static void ToBytes1ULongBE(ulong a, byte[] output, long o)
        {
            output[o + 0] = (byte)(a >> 56);
            output[o + 1] = (byte)(a >> 48);
            output[o + 2] = (byte)(a >> 40);
            output[o + 3] = (byte)(a >> 32);
            output[o + 4] = (byte)(a >> 24);
            output[o + 5] = (byte)(a >> 16);
            output[o + 6] = (byte)(a >> 08);
            output[o + 7] = (byte)(a >> 00);
        }

        static void ToBytes1UIntBE(uint a, byte[] output, long outputOffset)
        {
            long o = outputOffset;
            output[o + 0] = (byte)(a >> 24);
            output[o + 1] = (byte)(a >> 16);
            output[o + 2] = (byte)(a >> 08);
            output[o + 3] = (byte)(a >> 00);
        }

        static void ToBytesBE(long a, int bytesCount, byte[] output, long outputOffset)
        {
            for (int i = 0; i < bytesCount; i++)
            {
                output[outputOffset + bytesCount - 1 - i] = (byte)(a >> (i * 8));
            }
        }

        static void ThrowNotIn(int value, int[] validValues)
        {
            for (int i = 0; i < validValues.Length; i++) if (value == validValues[i]) return;

            throw new System.Exception("internal exception: value not in allowed range");
        }

        /*
         * TESTS 
         */

        public static void RUNTEST()
        {
            
            for (int i = 1; i < NIST_TESTS.Count; i++)
            {
                var test = NIST_TESTS[i];
                var c = CCMModeAlgorithm.Init(test.K);
                byte[] output = new byte[test.ExpectedOutput.Length];


                GenerationEncryption(c,
                    test.N, 0, test.N.Length,
                    test.P, 0, test.P.Length,
                    test.A, 0, test.A.Length,
                    output, 0,
                    test.TLEN);

                for (int j = 0; j < output.Length; j++)
                {
                    if (output[j] != test.ExpectedOutput[j]) throw new Exception("output != expected");
                }
            }
        }

        static List<CCMTest> NIST_TESTS = new List<CCMTest>()
        {
            new CCMTest(
                "404142434445464748494a4b4c4d4e4f",
                "10111213141516",
                "0001020304050607",
                "20212223",
                "7162015b4dac255d",
                4),
            new CCMTest(
                "404142434445464748494a4b4c4d4e4f",
                "1011121314151617",
                "000102030405060708090a0b0c0d0e0f",
                "202122232425262728292a2b2c2d2e2f",
                "d2a1f0e051ea5f62081a7792073d593d1fc64fbfaccd",
                6),
            new CCMTest(
                "404142434445464748494a4b4c4d4e4f",
                "101112131415161718191a1b",
                "000102030405060708090a0b0c0d0e0f10111213",
                "202122232425262728292a2b2c2d2e2f3031323334353637",
                "e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5484392fbc1b09951",
                8),
            Example4()
            
        };

        static CCMTest Example4()
        {
            byte[] a = new byte[524288];

            for (int i = 0; i < a.Length; i++)
            {
                a[i] = (byte)i;
            }

            var x = new CCMTest(
                "404142434445464748494a4b4c4d4e4f",
                "101112131415161718191a1b1c",
                "01",
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
                "69915dad1e84c6376a68c2967e4dab615ae0fd1faec44cc484828529463ccf72b4ac6bec93e8598e7f0dadbcea5b",
                 14);

            x.A = a;

            return x;
        }

        class CCMTest
        {
            public byte[] K;
            public byte[] N;
            public byte[] A;
            public byte[] P;
            public byte[] ExpectedOutput;
            public int TLEN;

            public CCMTest(string k, string n, string a, string p, string expOut, int tlen)
            {
                K = BinConverter.FromString(k);
                N = BinConverter.FromString(n);
                A = BinConverter.FromString(a);
                P = BinConverter.FromString(p);
                ExpectedOutput = BinConverter.FromString(expOut);
                TLEN = tlen;
            }
        }
    }
}
