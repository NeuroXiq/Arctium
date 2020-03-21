namespace Arctium.Cryptography.ASN1.Standards.X509.Types
{
    public struct DHPublicKey
    {
        /// <summary>
        /// Public key, y = g^x mod p
        /// </summary>
        public byte[] Value;
    }
}
