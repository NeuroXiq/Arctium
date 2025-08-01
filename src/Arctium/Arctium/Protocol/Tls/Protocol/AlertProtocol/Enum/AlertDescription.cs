namespace Arctium.Protocol.Tls.Protocol.AlertProtocol.Enum
{
    public enum AlertDescription : byte
    {
        CloseNotify = 0,
        UnexpectedMessage = 10,
        BadRecordMac = 20,
        DecryptionFailed = 21,
        RecordOverflow = 22,
        DecompressionFailure = 30,
        HandshakeFailure = 40,
        NoCertificate_RESERVED = 41,
        BadCertificate = 42,
        UnsupportedCertificate = 43,
        CertificateRevoked = 44,
        CertificateExpired = 45,
        CertificateUnknow = 46,
        IllegalParameter = 47,
        UnknowCa = 48,
        AccessDenied = 49,
        DecodeError = 50,
        DecryptError = 51,
        ExoirtRestriction_RESERVED = 60,
        ProtocolVersion = 70,
        InternalError = 80,
        UserCanceled = 90,
        NoRenegotiation = 100,
        UnrecognizedName = 112,
        NoApplicationProtocol = 120
    }
}
