namespace Arctium.Standards.Connection.Tls.Tls13.API.Extensions
{
    /// <summary>
    /// Configures GREASE on client side.
    /// Count numbers used in constructor are a maximum amounts of 
    /// GREASE values to inject to specific protocol field.
    /// Count can exceed length of values defined in GREASE standard (e.g. can be 999999)
    /// it will be truncated to valid value. It also can be zero
    /// (then no GREASE will be send for particular protocol filed)
    /// Values are selected randomly
    /// </summary>
    public class ExtensionClientConfigGREASE
    {
        public int CipherSuitesCount { get; private set; }
        public int ExtensionsCount { get; private set; }
        public int SupportedGroupsCount { get; private set; }
        public int KeyShareCount { get; private set; }
        public int SignatureAlgorithmsCount { get; private set; }
        public int SupportedVersionsCount { get; private set; }
        public int PskKeModesCount { get; private set; }
        public int ALPNCount { get; private set; }

        public ExtensionClientConfigGREASE(
            int cipherSuitesCount = 3,
            int extensionsCount = 3,
            int supportedGroupsCount = 3,
            int keyShareCount = 3,
            int signatureAlgorithmsCount = 3,
            int supportedVersionsCount = 3,
            int pskKeModesCount = 3,
            int alpnCount = 3)
        {
            CipherSuitesCount = cipherSuitesCount;
            ExtensionsCount = extensionsCount;
            SupportedGroupsCount = supportedGroupsCount;
            KeyShareCount = keyShareCount;
            SignatureAlgorithmsCount = signatureAlgorithmsCount;
            SupportedVersionsCount = supportedVersionsCount;
            PskKeModesCount = pskKeModesCount;
            ALPNCount = alpnCount;
        }
    }
}
