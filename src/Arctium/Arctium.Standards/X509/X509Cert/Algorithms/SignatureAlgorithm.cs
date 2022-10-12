namespace Arctium.Standards.X509.X509Cert.Algorithms
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

        // ecdsa
        ECDSAWithSHA384,
        ECDSAWithSHA224,
        ECDSAWithSHA256,
        ECDSAWithSHA512,
    }
}
