namespace Arctium.Standards.ArctiumLibShared
{
    public class RSAPrivateKeyCRT
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
    }
}
