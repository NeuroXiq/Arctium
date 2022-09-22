using Arctium.Shared.Helpers.Buffers;
using System;
using System.Numerics;

namespace Arctium.Cryptography.HashFunctions.MAC
{
    public static class Poly1305Algorithm
    {
        private static readonly BigInteger Num2_128;
        private static readonly BigInteger P;

        static Poly1305Algorithm()
        {
            Num2_128 = new BigInteger(1);
            Num2_128 = Num2_128 << 128;

            P = new BigInteger(1);
            P = (P << 130) - 5;
        }

        public class Context
        {
            public byte[] Block;
            public byte[] Input;
            public byte[] RClamped;
            public BigInteger R;
            public BigInteger S;
            public BigInteger Accumulator;
        }

        public static Context Initialize(byte[] keyMaterial)
        {
            if (keyMaterial.Length != 32) throw new Exception("internal: keymaterial % 16 != 0");

            Context c = new Context
            {
                Input = new byte[16],
                R = new BigInteger(0),
                S = new BigInteger(0),
                RClamped = new byte[16],
                Accumulator = new BigInteger(0)
            };

            Reset(c, keyMaterial);

            return c;
        }

        public static void Reset(Context c, byte[] keyMaterial)
        {
            c.Accumulator = 0;
            // c.S = new BigInteger(new ReadOnlySpan<byte>(keyMaterial, 8, 8), isUnsigned: true, isBigEndian: false);
            // c.R = new BigInteger(new ReadOnlySpan<byte>(keyMaterial, 8, 8), isUnsigned: true, isBigEndian: false);

            for (int i = 0; i < 16; i++) c.RClamped[i] = keyMaterial[i];

            c.RClamped[3] &= 15;
            c.RClamped[7] &= 15;
            c.RClamped[11] &= 15;
            c.RClamped[15] &= 15;

            c.RClamped[4] &= 252;
            c.RClamped[8] &= 252;
            c.RClamped[12] &= 252;

            c.R = new BigInteger(c.RClamped, isUnsigned: true, isBigEndian: false);
            c.S = new BigInteger(new ReadOnlySpan<byte>(keyMaterial, 16, 16), isUnsigned: true, isBigEndian: false);
        }

        public static void ProcessLastBlock(Context c,
            byte[] input,
            long inOffset,
            long length,
            byte[] output,
            long outOffs)
        {
            if (length > 17) throw new Exception("internal: must be less than 17 for last block");

            for (int i = 0; i < 16; i++) c.Input[i] = 0;
            for (int i = 0; i < length; i++) c.Input[i] = input[inOffset + i];

            BigInteger b;

            // append 1 bit before bytes (+= Num2_128 but not full block)

            if (length > 0)
            {
                if (length < 16) c.Input[length] = 0x01;

                b = new BigInteger(c.Input, isUnsigned: true, isBigEndian: false);

                if (length == 16) b += Num2_128;

                c.Accumulator += b;
                c.Accumulator *= c.R;
                c.Accumulator %= P;
            }

            c.Accumulator += c.S;

            byte[] hash = c.Accumulator.ToByteArray(isUnsigned: true, isBigEndian: false);

            int hashLen = hash.Length > 16 ? 16 : hash.Length; // only 16 bytes neede by spec

            for (int i = 0; i < 16; i++) output[i + outOffs] = 0;
            MemCpy.Copy(hash, 0, output, outOffs, hashLen);
        }

        public static void ProcessFullBlocks(Context c, byte[] input, long inOffset, long length)
        {
            if (length % 16 != 0 || length == 0) throw new Exception("internal: must be 16 len and greater than 0");

            for (int i = 0; i < length; i += 16)
            {
                for (int j = 0; j < 16; j++) c.Input[j] = input[inOffset + i + j];

                BigInteger b = new BigInteger(c.Input, isUnsigned: true, isBigEndian: false);

                b += Num2_128;

                c.Accumulator += b;
                c.Accumulator *= c.R;
                c.Accumulator %= P;
            }
        }
    }
}
