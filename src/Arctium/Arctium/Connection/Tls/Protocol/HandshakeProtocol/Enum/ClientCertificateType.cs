namespace Arctium.Standards.Connection.Tls.Protocol.HandshakeProtocol.Enum
{
    enum ClientCertificateType
    {
        RSA_sign = (1),
        DSS_sign = (2),
        RSA_fixed_dh = (3),
        DSS_fixed_dh =(4),
        RSA_ephemeral_dh_RESERVED = (5), 
        DSS_ephemeral_dh_RESERVED = (6),
        FORTEZZA_DMS_RESERVED = (20),
    }
}
