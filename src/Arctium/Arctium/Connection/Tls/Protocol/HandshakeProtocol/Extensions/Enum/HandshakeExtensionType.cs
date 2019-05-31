namespace Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions
{
    //
    // Copy-paste from IANA 
    // https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml

    public enum HandshakeExtensionType : ushort
    {
        ServerName = 0,
        MaxFragmentLength = 1,
        ClientCertificateUrl = 2,
        TrustedCaKeys = 3,
        TruncatedHmac = 4,
        StatusRequest = 5,
        UserMapping = 6,
        ClientAuthz = 7,
        ServerAuthz = 8,
        CertType = 9,
        EllipticCurves = 10,
        EcPointFormats = 11,
        Srp = 12,
        SignatureAlgorithms = 13,
        UseSrtp = 14,
        Heartbeat = 15,
        ApplicationLayerProtocolNegotiation = 16,
        StatusRequestV = 17,
        SignedCertificateTimestamp = 18,
        ClientCertificateType = 19,
        ServerCertificateType = 20,
        Padding = 21,
        EncryptThenMac = 22,
        ExtendedMasterSecret = 23,
        TokenBinding = 24,
        CachedInfo = 25,
        TlsLts = 26,
        CompressCertificate = 27,
        RecordSizeLimit = 28,
        PwdProtect = 29,
        PwdClear = 30,
        PasswordSalt = 31,
        SessionTicket = 35,
        PreSharedKey = 41,
        EarlyData = 42,
        SupportedVersions = 43,
        Cookie = 44,
        PskKeyExchangeModes = 45,
        CertificateAuthorities = 47,
        OidFilters = 48,
        PostHandshakeAuth = 49,
        SignatureAlgorithmsCert = 50,
        KeyShare = 51,
        TransparencyInf = 52,
    }
}
