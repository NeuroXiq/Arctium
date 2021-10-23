namespace Arctium.Standards.PKCS1.v2_2
{
    /// <summary>
    /// Leading zero bytes must be trimmed
    /// </summary>
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
