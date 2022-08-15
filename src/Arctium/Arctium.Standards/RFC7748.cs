using Arctium.Shared.Helpers.Buffers;
using System;
using System.Numerics;

namespace Arctium.Standards
{
    /// <summary>
    /// RFC 7748
    /// </summary>
    public static class RFC7748
    {
        // (2^255) - 19
        private static readonly BigInteger P_X22519 = (BigInteger.Pow(2, 255) - 19);
        private static readonly BigInteger A24_X25519 = 121665;

        private static readonly BigInteger P_X448 = (BigInteger.Pow(2, 448)) - (BigInteger.Pow(2,224)) - 1;
        private static readonly BigInteger A24_X448 = 39081;

        const int BITS_X25519 = 255;
        const int BITS_X448 = 448;

        private static readonly byte[] X25519_UCoord9 = new byte[] { 09, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00 };
        private static readonly byte[] X448_UCoord5 = new byte[]
        {
            05, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,
            00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,
        };

        public static byte[] X25519_UCoord_9(byte[] k) => X25519(k, X25519_UCoord9);

        public static byte[] X448_UCoord_5(byte[] k) => X448(k, X448_UCoord5);

        /// <summary>
        /// Returns encrypted secret key k as multiplication of u
        /// </summary>
        /// <param name="k">Secret key to encrypt</param>
        /// <param name="u">U Coordinate of elliptic curve (or secret received from other party)</param>
        /// <returns></returns>
        public static byte[] X25519(byte[] k, byte[] u)
        {
            BigInteger uAsInt = DecodeUCoordinate(u, BITS_X25519);
            BigInteger kAsInt = DecodeScalar25519(k);

            BigInteger resultAsInt = Compute(uAsInt, kAsInt, BITS_X25519, P_X22519, A24_X25519);

            byte[] result = EncodeUCoordinate(resultAsInt, BITS_X25519);

            return result;
        }

        static byte[] EncodeUCoordinate(BigInteger uCoord, int bits)
        {
            byte[] notAligned = uCoord.ToByteArray(true, false);

            int bytesLen = (bits + 7) / 8;
            byte[] result = new byte[bytesLen];

            MemCpy.Copy(notAligned, 0, result, 0, notAligned.Length);

            return result;
        }

        public static byte[] X448(byte[] k, byte[] u)
        {
            BigInteger uAsInt = DecodeUCoordinate(u, BITS_X448);
            BigInteger kAsInt = DecodeScalar448(k);

            BigInteger resultAsInt = Compute(uAsInt, kAsInt, BITS_X448, P_X448, A24_X448);

            byte[] result = EncodeUCoordinate(resultAsInt, BITS_X448);

            return result;
        }

        public static BigInteger DecodeScalar25519(byte[] k)
        {
            Throw(k.Length != 32, "k length != 32");

            byte[] scalar = new byte[32];
            MemCpy.Copy(k, 0, scalar, 0, 32);

            scalar[0] = (byte)(scalar[0] & 248);
            scalar[31] = (byte)(scalar[31] & 127);
            scalar[31] = (byte)(scalar[31] | 64);

            return DecodeLittleEndian(scalar, 0, 32);
        }

        public static BigInteger DecodeScalar448(byte[] k)
        {
            Throw(k.Length != 56, "448 scalan length not equal to 56");

            byte[] scalar = new byte[56];
            MemCpy.Copy(k, 0, scalar, 0, 56);

            scalar[0] = (byte)(scalar[0] & 252);
            scalar[55] = (byte)(scalar[55] | 128);

            return DecodeLittleEndian(scalar, 0, 56);
        }

        public static BigInteger DecodeUCoordinate(byte[] u, int bits)
        {
            int length = u.Length;
            byte[] ucoord = new byte[length];
            
            MemCpy.Copy(u, 0, ucoord, 0, length);

            // ignore unused bits
            if ((bits % 8) != 0)
            {
                ucoord[length - 1] = (byte)(ucoord[length - 1] & ((1 << (bits % 8)) - 1));
            }

            return DecodeLittleEndian(ucoord, 0, length);
        }

        static BigInteger Compute(BigInteger u,
            BigInteger k,
            int bits,
            BigInteger p,
            BigInteger a24)
        {
            BigInteger x_1 = u;
            BigInteger x_2 = 1;
            BigInteger z_2 = 0;
            BigInteger x_3 = u;
            BigInteger z_3 = 1;
            BigInteger swap = 0;

            BigInteger A, AA, B, BB, E, C, D, DA, CB;

            for (int t = bits - 1; t >= 0; t--)
            {
                BigInteger k_t = (k >> t) & 1;
                swap ^= k_t;

                cswap(swap, ref x_2, ref x_3);
                cswap(swap, ref z_2, ref z_3);

                swap = k_t;

                //A = (x_2 + z_2) % p;
                //AA = BigInteger.ModPow(A, 2, p);
                //B = (x_2 - z_2) % p;
                //BB = BigInteger.ModPow(B, 2, p);
                //E = (AA - BB) % p;
                //C = (x_3 + z_3) % p;
                //D = (x_3 - z_3) % p;
                //DA = (D * A) % p;
                //CB = (C * B) % p;
                //x_3 = BigInteger.ModPow((DA + CB), 2, p);
                //z_3 = (x_1 * BigInteger.ModPow(DA - CB, 2, p)) % p;
                //x_2 = (AA * BB) % p;
                //z_2 = (E * (AA + a24 * E)) % p;

                A = (x_2 + z_2); A = MOD(A, p);
                AA = BigInteger.ModPow(A, 2, p);
                B = (x_2 - z_2); B = MOD(B, p);
                BB = BigInteger.ModPow(B, 2, p);
                E = (AA - BB); E = MOD(E, p);
                C = (x_3 + z_3); C = MOD(C, p);
                D = (x_3 - z_3);  D = MOD(D, p);
                DA = (D * A); DA = MOD(DA, p);
                CB = (C * B); CB = MOD(CB, p);
                x_3 = BigInteger.ModPow((DA + CB), 2, p);
                z_3 = (x_1 * BigInteger.ModPow(MOD(DA - CB, p), 2, p)) % p;
                x_2 = (AA * BB); x_2 = MOD(x_2, p);
                z_2 = (E * (AA + a24 * E)); z_2 = MOD(z_2, p);
            }

            cswap(swap, ref x_2, ref x_3);
            cswap(swap, ref z_2, ref z_3);

            BigInteger result = (x_2 * (BigInteger.ModPow(z_2, p - 2, p))) % p;

            return result;
        }

        static BigInteger MOD(BigInteger value, BigInteger mod)
        {
            value = value % mod;

            if (value.Sign < 0)
            {
                value += mod;
            }

            if (value.Sign < 0)
            {
                var w = 5;
            }

            return value;
        }

        static void cswap(BigInteger swap,
            ref BigInteger x_2,
            ref BigInteger x_3)
        {
            if (swap == 1)
            {
                BigInteger temp = x_2;
                x_2 = x_3;
                x_3 = temp;
            }
        }


        static BigInteger DecodeLittleEndian(byte[] a, int start, int length)
        {
            BigInteger b = new BigInteger(new ReadOnlySpan<byte>(a, start, length), true, false);

            return b;
        }

        static void Throw(bool condition, string msg)
        {
            if (condition) throw new InvalidOperationException(msg);
        }
    }
}
