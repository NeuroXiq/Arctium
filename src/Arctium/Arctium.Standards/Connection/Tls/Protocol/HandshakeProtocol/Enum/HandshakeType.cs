﻿namespace Arctium.Standards.Connection.Tls.Protocol.HandshakeProtocol
{
    public enum HandshakeType : byte
    {
        HelloRequest= 0,
        ClientHello= 1,
        ServerHello= 2,
        Certificate= 11,
        ServerKeyExchange = 12,
        CertificateRequest= 13,
        ServerHelloDone= 14,
        CertificateVerify= 15,
        ClientKeyExchange= 16,
        Finished = 20
    }
}
