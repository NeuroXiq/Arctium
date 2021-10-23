namespace Arctium.Standards.PKCS1.v2_2
{
    /// <summary>
    /// Leading zeros must be removed (all filed except version must not start with zero byte, this is due internal implementation)
    /// </summary>
    public class RSAPrivateKey
    {
        public int Version;
        
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

        /// <summary>
        /// (inverse of q) mod p
        /// </summary>
        public byte[] Coefficient;
        public OtherPrimeInfo[] OtherPrimeInfos;
    }
}
