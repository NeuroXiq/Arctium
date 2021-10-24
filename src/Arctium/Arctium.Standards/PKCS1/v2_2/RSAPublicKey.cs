using System.Numerics;

namespace Arctium.Standards.PKCS1.v2_2
{
    public class RSAPublicKey
    {
        /// <summary>
        /// n
        /// </summary>
        public byte[] Modulus;

        /// <summary>
        /// e
        /// </summary>
        public byte[] PublicExponent;


        public RSAPublicKey(byte[] modulus, byte[] publicExponent)
        {
            Modulus = modulus;
            PublicExponent = publicExponent;
        }
    }
}
