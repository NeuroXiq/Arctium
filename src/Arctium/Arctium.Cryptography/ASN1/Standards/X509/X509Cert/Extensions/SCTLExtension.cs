namespace Arctium.Cryptography.ASN1.Standards.X509.X509Cert.Extensions
{
    //TODO X509/Extensions impelemnt this

    /// <summary>
    /// Represents Signed Certificate Timestamp List extension
    /// </summary>
    public class SCTLExtension : CertificateExtension
    {
        /// <summary>
        /// Raw bytes of the ExtValue field.
        /// </summary>
        public byte[] RawExtnValue;
        public SCTLExtension(byte[] rawInnerBytes,bool isCritical) : base(ExtensionType.SCTL, isCritical)
        {
            RawExtnValue = rawInnerBytes;
        }
    }
}
