using System.Numerics;

namespace Arctium.Cryptography.Ciphers.RSA
{
    public class RSAPublicKey
    {
        public BigInteger Modulus { get; private set; }
        public BigInteger PublicExponent { get; private set; }

        public RSAPublicKey(BigInteger modulus, BigInteger publicExponent)
        {
            Modulus = modulus;
            PublicExponent = publicExponent;
        }
    }
}
