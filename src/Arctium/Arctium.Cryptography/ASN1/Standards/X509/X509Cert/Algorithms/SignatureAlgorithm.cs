namespace Arctium.Cryptography.ASN1.Standards.X509.X509Cert
{
    public enum SignatureAlgorithm
    {
        SHA1WithRSAEncryption,
        DSAWithSha1,
        ECDSAWithSHA1,

        // RSA
        SHA224WithRSAEncryption,
        SHA384WithRSAEncryption,
        SHA512WithRSAEncryption,
        SHA256WithRSAEncryption,
        MD2WithRSAEncryption,
        MD5WithRSAEncryption,
    }
}
