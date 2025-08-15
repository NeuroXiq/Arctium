using Arctium.Shared;
using System;
using System.Collections.Generic;

namespace Arctium.Cryptography.Ciphers.BlockCiphers.Algorithms
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

        const int BlockSize16 = 16;

        public class Context
        {
            public BlockCipher Cipher;
            public byte[] CtrEnc;
            public byte[] Ctr;
            public byte[] Tag;
            // public byte[] Key;

        }

        public static Context Init(BlockCipher cipher)
        {
            var context = new Context();
            context.Cipher = cipher;
            context.CtrEnc = new byte[BlockSize16];
            context.Ctr = new byte[BlockSize16];
            context.Tag = new byte[16];
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

        public static void DecryptionVerification(Context context,
            byte[] nonce, long nonceOffset, long nonceLength,
            byte[] ciphertext, long ciphertextOffset, long ciphertextLength,
            byte[] a, long aOffset, long aLength,
            byte[] plaintextOutput, long plaintextOutputOffset,
            byte[] tag, long tagOffset,
            int tagLength,
            out bool tagValid)
        {
            long fullBlocks = ciphertextLength / BlockSize16;
            long lastBlock = ciphertextLength - fullBlocks;
            byte[] ctrEnc = context.CtrEnc, ctr = context.CtrEnc;
            BlockCipher ciph = context.Cipher;
            int ctri = 1, q = 15 - nonce.Length;

            ctr[0] = (byte)(q - 1);
            Array.Copy(nonce, 0, ctr, 1, nonce.Length);

            long io = ciphertextOffset;
            long oo = plaintextOutputOffset;

            for (int i = 0; i < fullBlocks; i += BlockSize16)
            {
                ctri++;
                ToBytesBE(ctri, q, ctr, 16 - q);
                ciph.Encrypt(ctr, 0, ctrEnc, 0, 16);
                Xor(ciphertext, io, ctrEnc, 0, plaintextOutput, oo);
                io += 16; oo += 16;
            }

            if (lastBlock > 0)
            {
                ctri++;
                ToBytesBE(ctri, q, ctr, 16 - q);
                ciph.Encrypt(ctr, 0, ctrEnc, 0, 16);
                Xor(ciphertext, io, ctrEnc, 0, plaintextOutput, oo);
            }

            ToBytesBE(0, q, ctr, 16 - q);
            byte[] t = context.Tag;
            byte[] computedT = new byte[16];

            ciph.Encrypt(ctr, 0, ctrEnc, 0, 16);
            Xor(tag, tagOffset, ctrEnc, 0, t, 0, tagLength);

            ComputeT(context, nonce, nonceOffset, nonceLength,
                plaintextOutput, plaintextOutputOffset, ciphertextLength,
                a, aOffset, aLength,
                tagLength, computedT);

            bool isTagValid = true;
            for (int i = 0; i < tagLength; i++) isTagValid &= t[i] == computedT[i];

            tagValid = isTagValid;
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
            long outputOffset,
            byte[] tagOutput,
            long tagOutputOffset,
            int t)
        {
            ByteBuf buf = new ByteBuf();

            byte[] T = new byte[16];
            ComputeT(context, nonce, nonceOffset, nonceLength,
                payload, payloadOffset, payloadLength,
                associatedData, associatedDataOffset, associatedDataLengt, t, T);

            AES aes = (AES)context.Cipher;

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
                tagOutput[tagOutputOffset + j] = T[j]; 
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

                // blad w nist jest 0x01 a tutaj 0x08 dodaje
                // blok 1 (b1)
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

            AES aes = (AES)context.Cipher;
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

        //public static void RUNTEST()
        //{
            
        //    for (int i = 1; i < NIST_TESTS.Count; i++)
        //    {
        //        var test = NIST_TESTS[i];
        //        var c = CCMModeAlgorithm.Init(new AES(test.K));
        //        byte[] output = new byte[test.ExpectedOutput.Length];


        //        GenerationEncryption(c,
        //            test.N, 0, test.N.Length,
        //            test.P, 0, test.P.Length,
        //            test.A, 0, test.A.Length,
        //            output, 0,
        //            output, test.P.Length - test.TLEN,
        //            test.TLEN);

        //        for (int j = 0; j < output.Length; j++)
        //        {
        //            if (output[j] != test.ExpectedOutput[j]) throw new Exception("output != expected");
        //        }
        //    }
        //}

        
    }
}
