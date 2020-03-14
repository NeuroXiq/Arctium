namespace Arctium.Encoding.IDL.ASN1.Standards.X509.X509Certificate
{
    public enum X509CertExtensionType
    {
        /// <summary>
        /// This special value indicates, that 
        /// extension is not defined/supported by current implementation.
        /// Therefore class representing this extension do not exists.
        /// </summary>
        Unrecognized,
        KeyIdentifier,
        BasicConstraint,
        NameConstraint,
        ExtendedKeyUsage,
        InhibitAntipolicy,
        SubjectAlternativeName,
        KeyUsage,
        CertificatePolicy,
        Authority,
        SubjectKeyIdentifier,
        Policy
    }
}
