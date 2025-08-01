namespace Arctium.Protocol.Tls13.APIModel
{
    public enum ExtensionType
    {
        /// <summary>
        /// Extension unknown or not supported in current implementation
        /// </summary>
        UnknownExtension,

        /// <summary>
        /// (RFC 8446)
        /// </summary>
        OidFilters,

        /// <summary>
        /// (RFC 8446)
        /// </summary>
        SignatureAlgorithms,

        CertificateAuthorities,
    }
}
