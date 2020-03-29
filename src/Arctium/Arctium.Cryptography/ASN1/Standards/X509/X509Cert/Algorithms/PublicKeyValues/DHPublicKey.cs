namespace Arctium.Cryptography.ASN1.Standards.X509.X509Cert
{
    public struct DHPublicKey
    {
        /// <summary>
        /// Public key, y = g^x mod p
        /// </summary>
        public byte[] Value;
    }
}
