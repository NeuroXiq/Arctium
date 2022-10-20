using Arctium.Standards.PKCS1.v2_2;

namespace Arctium.Standards.ArctiumLibShared
{
    public class RSAPrivateKeyCRT : IArctiumConvertable<PKCS1.v2_2.PKCS1v2_2API.PrivateKeyCRT>
    {
        /// <summary>
        /// N / Represents RSA Modulus
        /// </summary>
        public byte[] Modulus;

        /// <summary>
        /// e
        /// </summary>
        public byte[] PublicExponent;

        /// <summary>
        /// d
        /// </summary>
        public byte[] PrivateExponent;

        /// <summary>
        /// p
        /// </summary>
        public byte[] Prime1;

        /// <summary>
        /// q
        /// </summary>
        public byte[] Prime2;

        /// <summary>
        /// d mod p - 1
        /// </summary>
        public byte[] Exponent1;

        /// <summary>
        /// d mod q - 1
        /// </summary>
        public byte[] Exponent2;

        PKCS1v2_2API.PrivateKeyCRT IArctiumConvertable<PKCS1v2_2API.PrivateKeyCRT>.Convert()
        {
            var c = new PKCS1.v2_2.RSAPrivateKey();

            c.Modulus = Modulus;
            c.PublicExponent = PublicExponent;
            c.PrivateExponent = PrivateExponent;
            c.Prime1 = Prime1;
            c.Prime2 = Prime2;
            c.Exponent1 = Exponent1;
            c.Exponent2 = Exponent2;

            return new PKCS1v2_2API.PrivateKeyCRT(c);
        }
    }
}
