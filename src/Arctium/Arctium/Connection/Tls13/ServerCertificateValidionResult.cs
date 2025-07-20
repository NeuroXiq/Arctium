namespace Arctium.Standards.Connection.Tls13
{
    /// <summary>
    /// Result of validation server certificate on client side. See TLS 13 documentation (RFC 8446)
    /// </summary>
    public enum ServerCertificateValidionResult
    {
        /// <summary>
        /// certificate is valid
        /// </summary>
        Success,

        /// <summary>
        ///  unknown_ca: A valid certificate chain or partial chain was received,
        /// but the certificate was not accepted because the CA certificate
        /// could not be located or could not be matched with a known trust
        /// anchor.
        /// </summary>
        Invalid_UnknownCA,

        /// <summary>
        /// Certificate is invalid and kind of problem 
        /// is not listed in that enu,
        /// </summary>
        Invalid_OtherReason,

        /// <summary>
        /// 
        /// </summary>
        Invalid_BadCertificateStatusResponse,

        /// <summary>
        /// certificate_unknown: Some other (unspecified) issue arose in
        /// processing the certificate, rendering it unacceptable.
        /// </summary>
        Invalid_CertificateUnknown,

        /// <summary>
        /// certificate_expired: A certificate has expired or is not currently
        /// valid.
        /// </summary>
        Invalid_CertificateExpired,

        /// <summary>
        /// certificate_revoked: A certificate was revoked by its signer.
        /// </summary>
        Invalid_CertificateRevoked,

        /// <summary>
        ///  unsupported_certificate: A certificate was of an unsupported type.
        /// </summary>
        Invalid_UnsupportedCertificate,

        /// <summary>
        /// bad_certificate: A certificate was corrupt, contained signatures
        /// that did not verify correctly, etc.
        /// </summary>
        Invalid_BadCertificate,
    }
}
