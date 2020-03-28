namespace Arctium.Cryptography.ASN1.Standards.X509.X509Cert
{
    /// <summary>
    /// Represents type of the <see cref="CertificateExtension"/> object
    /// </summary>
    public enum ExtensionType
    {
        AuthorityKeyIdentifier,
        KeyIdentifier,
        /// <summary>
        /// Basic constraints extension type
        /// </summary>
        BasicConstraints,
        NameConstraint,
        ExtendedKeyUsage,
        InhibitAntipolicy,
        KeyUsage,
        CertificatePolicy,
        Authority,
        SubjectKeyIdentifier,
        Policy,
        /// <summary>
        /// X509 Subject Alternative Name extension type
        /// </summary>
        SubjectAltName,
        CRLDistributionPoints,
        AuthorityInfoAccess,
        /// <summary>
        /// Signed certificate timestamp list (certificate transparenct)
        /// </summary>
        SCTL
    }
}
