using Arctium.Cryptography.Ciphers.Asymmetric.Algorithms;
using System;
using System.Collections.Generic;
using System.Text;

namespace Arctium.Cryptography.Ciphers.Asymmetric
{
    public class RSA
    {
        private RSAAlgorithm.RSAPublicKey publicKey;
        private RSAAlgorithm.RSAPrivateKey privateKey;

        public RSA(byte[] e, byte[] n)
        {
            publicKey = RSAAlgorithm.CreatePublicKey(e, n);
        }

        public RSA(byte[] dP, byte[] dQ, byte[] qinv, byte[] n)
        {

        }

        public byte[] EncryptByPublicKey(byte[] buffer, long offset, long length) => RSAAlgorithm.EncryptByPublicKey(publicKey, buffer, offset, length);

        public void DecrytpByPublicKey(byte[] input, long offset, long length)
        {
        }

        public void EncryptByPrivateKey(byte[] buffer, long offset, long length)
        {
        }

        public void DecrytpByPrivateKey(byte[] input, long offset, long length)
        {
        }
    }
}
