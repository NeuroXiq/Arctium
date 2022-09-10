namespace Arctium.Connection.Tls.Tls13.Model
{
    enum HandshakeType : byte
    {
        HelloRequest_RESERVED = 0,
        ClientHello = 1,
        ServerHello = 2,
        HelloVerifyRequest_RESERVED = 3,
        NewSessionTicket = 4,
        EndOfEarlyData = 5,
        HelloRetryRequest_RESERVED = 6,
        EncryptedExtensions = 8,
        Certificate = 11,
        ServerKeyExchange_RESERVED = 12,
        CertificateRequest = 13,
        ServerHelloDone_RESERVED = 14,
        CertificateVerify = 15,
        ClientKeyExchange_RESERVED = 16,
        Finished = 20,
        CertificateUrl_RESERVED = 21,
        CertificateStatus_RESERVED = 22,
        SupplementalData_RESERVED = 23,
        KeyUpdate = 24,
        MessageHash = 254,
        HelloRetryRequest_ARCTIUM_INTERNAL_TEMPORARY = 253,
    }
}
