using Arctium.Standards.ArctiumLibShared;

namespace Arctium.Standards.PKCS1.v2_2
{
    /// <summary>
    /// PKCS v 2.2 RSA private key (as RFC defines)
    /// Stored for example in '-- BEGIN RSA PRIVATE KEY ---' PEM files
    /// Can be decoded by PKCS1_v2_2_API static method
    /// </summary>
    public class RSAPrivateKey : IArctiumConvertable<ArctiumLibShared.RSAPrivateKeyCRT>
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


        /// <summary>
        /// Convert ignores <see cref="OtherPrimeInfo"/> because it is impossible (there is no corresponding field in result class)
        /// </summary>
        /// <returns>Current object converter into other</returns>
        public RSAPrivateKeyCRT Convert()
        {
            var sk = new RSAPrivateKeyCRT();

            sk.Modulus = this.Modulus;
            sk.PublicExponent = this.PublicExponent;
            sk.PrivateExponent = this.PrivateExponent;
            sk.Prime1 = this.Prime1;
            sk.Prime2 = this.Prime2;
            sk.Exponent1 = this.Exponent1;
            sk.Exponent2 = this.Exponent2;
            sk.Coefficient = this.Coefficient;

            return sk;
        }
    }
}
