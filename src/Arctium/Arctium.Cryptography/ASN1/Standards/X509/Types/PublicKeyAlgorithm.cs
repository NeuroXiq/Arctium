namespace Arctium.Cryptography.ASN1.Standards.X509.Types
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
