namespace Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions
{
    public enum HandshakeExtensionType : ushort
    { 
        ServerName = 0,
        MaxFragmentLength = 1,
        ClientCertifiateUrl = 2,
        TrustedCsKeys = 3,
        TruncateHmac = 4,
        SignatureAlgorithms = 13,
        ALPN = 16
    }
}
