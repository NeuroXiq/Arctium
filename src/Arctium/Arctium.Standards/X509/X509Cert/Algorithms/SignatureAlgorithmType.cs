namespace Arctium.Standards.X509.X509Cert.Algorithms
{
    public enum SignatureAlgorithmType
    {
        DSAWithSha1,

        // RSA
        SHA1WithRSAEncryption,
        SHA224WithRSAEncryption,
        SHA384WithRSAEncryption,
        SHA512WithRSAEncryption,
        SHA256WithRSAEncryption,
        MD2WithRSAEncryption,
        MD5WithRSAEncryption,

        // ecdsa
        ECDSAWithSHA1,
        ECDSAWithSHA384,
        ECDSAWithSHA224,
        ECDSAWithSHA256,
        ECDSAWithSHA512,
    }
}
