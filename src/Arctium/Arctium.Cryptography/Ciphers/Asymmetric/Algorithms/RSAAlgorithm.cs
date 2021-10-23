using System;
using System.Numerics;

namespace Arctium.Cryptography.Ciphers.Asymmetric.Algorithms
{
    public static class RSAAlgorithm
    {
        public class RSAPublicKey
        {
            public BigInteger n;
            public BigInteger e;
        }

        public class RSAPrivateKey
        {
            public BigInteger dP;
            public BigInteger dQ;
            public BigInteger qinv;
            public BigInteger n;
        }

        public static RSAPublicKey CreatePublicKey(byte[] e, byte[] n)
        {
            return new RSAPublicKey()
            {
                n = new BigInteger(new ReadOnlySpan<byte>(n), true, true),
                e = new BigInteger(new ReadOnlySpan<byte>(e), true, true)
            };
        }

        public static RSAPrivateKey CreatePrivateKey(byte[] dp, byte[] dq, byte[] qinv, byte[] n)
        {
            throw new Exception();
        }

        public static byte[] EncryptByPublicKey(RSAPublicKey key, byte[] input, long inputOffset, long length)
        {
            BigInteger toEncrypt = new BigInteger(new ReadOnlySpan<byte>(input, (int)inputOffset, (int)length), true, true);

            BigInteger encrypted = BigInteger.ModPow(toEncrypt, key.e, key.n);

            byte[] result = encrypted.ToByteArray(true, true);

            return result;
        }

        public static void DecryptByPublicKey(RSAPublicKey key, byte[] data, long offset, long length)
        {

        }

        public static void EncryptByPublicKey(RSAPrivateKey key, byte[] input, long inputOffset, long length)
        {
            byte[] toEncrypt = new byte[length];
        }

        public static void DecryptByPublicKey(RSAPrivateKey key, byte[] data, long offset, long length)
        {

        }

        // Private
    }
}
