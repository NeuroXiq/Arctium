using Arctium.Shared.Helpers;
using Arctium.Shared.Helpers.Buffers;
using System.Diagnostics;

namespace Arctium.Cryptography.Ciphers.BlockCiphers.Algorithms
{
    public static class GaloisCounterModeAlgorithm
    {
        static readonly byte[] Zero16Bytes = new byte[16];
        const long BlockSize = 16;

        // Most significant bits of 'R' constant from NIST publication
        // all other bits on right (next 15 bytes) are zeros
        const byte R = 0xE1;

        public class Context
        {
            // public byte[] HashSubkey;
            public BlockCipher Cipher;
            public byte[] GHASH_Y;
            public byte[] H;
            public byte[] IV;
            public byte[] ICB;
            public byte[] J0;
            public byte[] T;
            public byte[][] GF_MUL_LOOKUP;
            public byte[] Temp1;
            public byte[] Temp2;
        }

        public static Context Initialize(BlockCipher cipher)
        {
            var ctx = new Context()
            {
                // HashSubkey = hashSubkey,
                Cipher = cipher,
                H = new byte[16],
                IV = new byte[16],
                GHASH_Y = new byte[16],
                ICB = new byte[16],
                T = new byte[16],
                J0 = new byte[16],
                GF_MUL_LOOKUP = new byte[16][],
                Temp1 = new byte[16],
                Temp2 = new byte[16]
            };

            for (int i = 0; i < 16; i++) ctx.GF_MUL_LOOKUP[i] = new byte[256 * 16];

            Reset(ctx);

            return ctx;
        }

        public static void Reset(Context context)
        {
            context.Cipher.Encrypt(Zero16Bytes, 0, context.H, 0, 16);
            CreateLookupTables(context);
        }

        static void CreateLookupTables(Context context)
        {
            byte[] t = context.Temp1;

            for (int i = 0; i < 16; i++)
            {
                MemOps.MemsetZero(t);
                for (int j = 0; j < 256; j++)
                {
                    t[i] = (byte)j;

                    GFMUL_NotOptimized(t, context.H, context.GF_MUL_LOOKUP[i], j * 16);
                }
            }
        }

        public static void AD(Context context,
            byte[] iv, long ivOffs, long ivLen,
            byte[] ciph, long ciphOffs, long ciphLen,
            byte[] a, long aOffs, long aLen,
            byte[] decryptOut, long decryptOutOffset,
            byte[] authTag, long authTagOffs, long authTagLen,
            out bool authTagValidationResult)
        {
            if (authTagLen > 16) throw new System.Exception("internal: auth tag lenght > 16");

            ComputeJ0(context, iv, ivOffs, ivLen);

            MemCpy.Copy(context.J0, context.ICB);
            inc32(context.ICB);

            GCTR(context, ciph, ciphOffs, ciphLen, decryptOut, decryptOutOffset);

            ComputeTTag(context, ciph, ciphOffs, ciphLen, a, aOffs, aLen);

            authTagValidationResult = true;

            for (int i = 0; i < authTagLen; i++) authTagValidationResult &= authTag[authTagOffs + i] == context.T[i];
        }

        static void ComputeJ0(Context context,
            byte[] iv, long ivOffs, long ivLen)
        {
            
            byte[] j0 = context.J0;

            if (ivLen == 12)
            {
                j0[15] = 1;
                MemCpy.Copy(iv, ivOffs, j0, 0, 12);
            }
            else
            {
                int rem = (int)(16 - (ivLen % 16));
                rem = rem == 16 ? 0 : rem;
                byte[] temp = new byte[ivLen + rem + 16];

                MemCpy.Copy(iv, ivOffs, temp, 0, ivLen);
                MemMap.ToBytes1ULongBE((ulong)(ivLen * 8), temp, temp.Length - 8);

                MemOps.MemsetZero(context.GHASH_Y);
                GHASH(context, temp, 0, temp.Length);
                MemCpy.Copy(context.GHASH_Y, 0, j0, 0, 16);
            }
        }

        static void ComputeTTag(Context context, 
            byte[] ciph, long ciphOffs, long ciphLen,
            byte[] a, long aOffs, long aLen)
        {
            long u = 16 - (ciphLen % 16);
            long v = 16 - (aLen % 16);
            u = u == 16 ? 0 : u;
            v = v == 16 ? 0 : v;

            byte[] temp_lens = new byte[16];
            MemMap.ToBytes1ULongBE((ulong)aLen * 8, temp_lens, 0);
            MemMap.ToBytes1ULongBE((ulong)ciphLen * 8, temp_lens, 8);

            MemOps.MemsetZero(context.GHASH_Y);

            long aLenFullBlocks = (aLen / 16) * 16;
            long aLenRem = aLen % 16;
            long cLenFullBlocks = (ciphLen / 16) * 16;
            long cLenRem = ciphLen % 16;

            GHASH(context, a, aOffs, aLenFullBlocks);

            if (aLenRem > 0)
            {
                byte[] temp1 = new byte[16];
                MemCpy.Copy(a, aOffs + aLenFullBlocks, temp1, 0, aLenRem);
                GHASH(context, temp1, 0, 16);
            }

            GHASH(context, ciph, ciphOffs, cLenFullBlocks);

            if (cLenRem > 0)
            {
                byte[] temp2 = new byte[16];
                MemCpy.Copy(ciph, ciphOffs + cLenFullBlocks, temp2, 0, cLenRem);
                GHASH(context, temp2, 0, 16);
            }

            GHASH(context, temp_lens, 0, 16);

            MemCpy.Copy(context.J0, context.ICB);

            GCTR(context, context.GHASH_Y, 0, 16, context.T, 0);
        }

        public static void AE(Context context,
        byte[] iv, long ivOffs, long ivLen,
        byte[] p, long pOffs, long pLen,
        byte[] a, long aOffs, long aLen,
        byte[] ciphOutput, long ciphOutOffset,
        byte[] authTagOut, long authTagOutOffs,
        int tagLengthInBytes)
        {
            ComputeJ0(context, iv, ivOffs, ivLen);
            byte[] j0 = context.J0;

            MemCpy.Copy(j0, context.ICB);
            inc32(context.ICB);

            GCTR(context, p, pOffs, pLen, ciphOutput, ciphOutOffset);
            ComputeTTag(context, ciphOutput, ciphOutOffset, pLen, a, aOffs, aLen);

            MemCpy.Copy(context.T, 0, authTagOut, authTagOutOffs, tagLengthInBytes);
        }

        static void GCTR(Context context,
        byte[] input,
        long inputOffset,
        long inputLength,
        byte[] output,
        long outputOffset)
        {
            if (inputLength == 0) return;

            long n = inputLength / 16;
            byte[] ctr = new byte[16];
            MemCpy.Copy(context.ICB, ctr);
            byte[] ctrEnc = new byte[16];

            long o = outputOffset;
            long io = inputOffset;
            for (long i = 0; (i + 16) <= inputLength; o += 16, io += 16, i += 16)
            {
                context.Cipher.Encrypt(ctr, 0, ctrEnc, 0, 16);
                for (long a = 0; a < 16; a++) output[o + a] = (byte)(ctrEnc[a] ^ input[a + io]);
                inc32(ctr);
            }

            long rem = inputLength % 16;

            if (rem != 0)
            {
                context.Cipher.Encrypt(ctr, 0, ctrEnc, 0, 16);
                for (long i = 0; i < rem; i++) output[o + i] = (byte)(input[io + i] ^ ctrEnc[i]);
            }
        }


        public static void GHASH(Context context,
        byte[] input,
        long inputOffset,
        long inputLength)
        {
            if (inputLength % 16 != 0) throw new System.Exception("INTERNAL: must be 16 length");

            byte[] y = context.GHASH_Y;
            byte[] tempMulOutput = context.Temp2;

            for (long i = inputOffset; i < inputLength + inputOffset; i += BlockSize)
            {
                for (long j = 0; j < BlockSize; j++) y[j] ^= input[i + j];

                // GFMUL_NotOptimized(y, context.H, tempMulOutput);
                GFMUL_Optimized(context, y, tempMulOutput);
                MemCpy.Copy(tempMulOutput, 0, y, 0, BlockSize);
            }

            // MemCpy.Copy(y, 0, output, outputOffset, BlockSize);
        }

        static void inc32(byte[] ctr)
        {
            uint c = MemMap.ToUInt4BytesBE(ctr, 12);
            c++;
            MemMap.ToBytes1UIntBE(c, ctr, 12);
        }


        static void GFMUL_Optimized(Context context, byte[] x, byte[] outputResult)
        {
            MemOps.MemsetZero(outputResult);
            for (int i = 0; i < 16; i++)
                for (int j = 0; j < 16; j++)
                    outputResult[j] ^= (byte)context.GF_MUL_LOOKUP[i][(x[i] *  16) + j];
        }

        //todo: maybe use ULONG to operate (will be faster?)
        public static void GFMUL_NotOptimized(byte[] x, byte[] num2, byte[] outputResult, int outOffset)
        {
            byte[] v = new byte[16];
            byte[] r = new byte[16];
            MemCpy.Copy(num2, v);

            MemOps.MemsetZero(outputResult, 0, 16);
            for (int i = 0; i < BlockSize; i++)
            {
                byte xbyte = x[i];

                for (int j = 0; j < 8; j++)
                {
                    byte vb = v[15];
                    bool xbit = ((int)xbyte & (1 << (7 - j))) != 0;
                    bool vbit = ((int)vb & 1) != 0;

                    if (xbit)
                    {
                        for (int a = 0; a < 16; a++) r[a] ^= v[a];
                    }

                    v[15] = (byte)(v[15] >> 1);

                    for (int a = 14; a >= 0; a--)
                    {
                        if ((v[a] & 1) != 0) v[a + 1] |= 0x80;
                        v[a] >>= 1;
                    }

                    if (vbit)
                    {
                        v[0] ^= R;
                    }
                }
            }

            MemCpy.Copy(r, 0, outputResult, outOffset, 16);
        }
    }
}
