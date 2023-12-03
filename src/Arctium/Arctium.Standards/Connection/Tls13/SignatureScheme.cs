namespace Arctium.Standards.Connection.Tls13
{
    /// <summary>
    /// Represents Signature scheme that are used to generate signature in CertificateVerify message or 
    /// acceptable certificate (see extnsions: signature_algorithms and signature_algorithms_cert for TLS 1.3)
    /// </summary>
    public enum SignatureScheme
    {
        EcdsaSecp256r1Sha256 = 0x0403,
        EcdsaSecp384r1Sha384 = 0x0503,
        EcdsaSecp521r1Sha512 = 0x0603,
        /* RSASSA-PSS algorithms with public key OID rsaEncryption */
        RsaPssRsaeSha256 = 0x0804,
        RsaPssRsaeSha384 = 0x0805,
        RsaPssRsaeSha512 = 0x0806,

        ///* EdDSA algorithms */
        //Ed25519 = 0x0807,
        //Ed448 = 0x0808,
        ///* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
        //RsaPssPssSha256 = 0x0809,
        //RsaPssPssSha384 = 0x080a,
        //RsaPssPssSha512 = 0x080b,
        ///* Legacy algorithms */
        //RsaPkcs1Sha1 = 0x0201,
        //EcdsaSha1 = 0x0203,
        ///* Reserved Code Points */
        //PrivateUse = 0xFE00 /* 0xFE00..0xFFFF*/,
    }
}
