namespace Arctium.Connection.Tls.Tls13.Model
{
    public enum AlertDescription {
        CloseNotify = 0,
        UnexpectedMessage = 10,
        BadRecordMac = 20,
        RecordOverflow = 22,
        HandshakeFailure = 40,
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
        UnsupportedExtension = 110,
        UnrecognizedName = 112,
        BadCertificateStatusResponse = 113,
        UnknownPskIdentity = 115,
        CertificateRequired = 116,
        NoApplicationProtocol = 120
 }
}
