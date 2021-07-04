namespace Arctium.Standards.ASN1.Standards.X509.X509Cert
{
    public class RSAPublicKey
    {
        public byte[] Modulus;
        public byte[] PublicExponent;

        internal RSAPublicKey(byte[] modulus, byte[] publicExponent)
        {
            Modulus = modulus;
            PublicExponent = publicExponent;
        }
    }
}
