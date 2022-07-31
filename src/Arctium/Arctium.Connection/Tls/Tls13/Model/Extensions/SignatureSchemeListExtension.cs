namespace Arctium.Connection.Tls.Tls13.Model.Extensions
{
    class SignatureSchemeListExtension : Extension
    {
        public override ExtensionType ExtensionType => ExtensionType.SignatureAlgorithms;

        public SignatureScheme[] Schemes { get; private set; }

        public enum SignatureScheme : ushort
        {
            /* RSASSA-PKCS1-v1_5 algorithms */
            RsaPkcs1Sha256 = 0x0401,
            RsaPkcs1Sha384 = 0x0501,
            RsaPkcs1Sha512 = 0x0601,
            /* ECDSA algorithms */
            EcdsaSecp256r1Sha256 = 0x0403,
            EcdsaSecp384r1Sha384 = 0x0503,
            EcdsaSecp521r1Sha512 = 0x0603,
            /* RSASSA-PSS algorithms with public key OID rsaEncryption */
            RsaPssRsaeSha256 = 0x0804,
            RsaPssRsaeSha384 = 0x0805,
            RsaPssRsaeSha512 = 0x0806,
            /* EdDSA algorithms */
            Ed25519 = 0x0807,
            Ed448 = 0x0808,
            /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
            RsaPssPssSha256 = 0x0809,
            RsaPssPssSha384 = 0x080a,
            RsaPssPssSha512 = 0x080b,
            /* Legacy algorithms */
            RsaPkcs1Sha1 = 0x0201,
            EcdsaSha1 = 0x0203,
            /* Reserved Code Points */
            PrivateUse = 0xFE00 /* 0xFE00..0xFFFF*/,
        }

        public SignatureSchemeListExtension(SignatureScheme[] schemes)
        {
            this.Schemes = schemes;
        }
    }
}
