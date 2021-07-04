namespace Arctium.Standards.ASN1.Standards.X509.X509Cert.Extensions
{
    /// <summary>
    /// Represents type of the <see cref="CertificateExtension"/> object
    /// </summary>
    public enum ExtensionType
    {
        /// <summary>
        /// Special purpose extensions type. Indicates undefined/unknown extenions 
        /// in current implementation of X509 standard
        /// </summary>
        Unknown,

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
