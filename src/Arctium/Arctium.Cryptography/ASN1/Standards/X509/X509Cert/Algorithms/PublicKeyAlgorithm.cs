namespace Arctium.Cryptography.ASN1.Standards.X509.X509Cert
{
    public enum PublicKeyAlgorithm
    {
        ECPublicKey,
        rsaEncryption,
        dhpublicnumber,
        /// <summary>
        /// ECDSA and ECDH public keys
        /// </summary>
        ecPublicKey
    }
}
