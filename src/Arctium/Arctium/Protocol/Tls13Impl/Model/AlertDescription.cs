namespace Arctium.Protocol.Tls13Impl.Model
{
    public enum AlertDescription : byte
    {
        CloseNotify = 0,
        UnexpectedMessage = 10,
        BadRecordMac = 20,
        RecordOverflow = 22,

        /// <summary>
        ///  Receipt of a "handshake_failure" alert message
        /// indicates that the sender was unable to negotiate an acceptable
        /// set of security parameters given the options available.
        /// </summary>
        HandshakeFailure = 40,

        /// <summary>
        /// bad_certificate: A certificate was corrupt, contained signatures that did not verify correctly, etc.
        /// </summary>
        BadCertificate = 42,
        UnsupportedCertificate = 43,
        CertificateRevoked = 44,
        CertificateExpired = 45,
        CertificateUnknown = 46,
        Illegal_parameter = 47,
        UnknownCa = 48,
        AccessDenied = 49,
        DecodeError = 50,
        DecryptError = 51,
        ProtocolVersion = 70,
        InsufficientSecurity = 71,
        InternalError = 80,
        InappropriateFallback = 86,
        UserCanceled = 90,
        MissingExtension = 109,

        /// <summary>
        /// When endpoints send extension (eg server) 
        /// but this extension was not offered by client.
        /// Not applicable for cookie extension because
        /// server sends first
        /// </summary>
        UnsupportedExtension = 110,

        /// <summary>
        /// RFC 6066 Server Name Indication, send when 
        /// server name is recognized/configured 
        /// that is listed in 'server name indication' client hello extension
        /// </summary>
        UnrecognizedName = 112,
        BadCertificateStatusResponse = 113,
        UnknownPskIdentity = 115,
        CertificateRequired = 116,

        /// <summary>
        /// rfc7301
        /// </summary>
        NoApplicationProtocol = 120
    }
}
