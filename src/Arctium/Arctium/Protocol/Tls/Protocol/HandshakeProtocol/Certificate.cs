﻿using System.Security.Cryptography.X509Certificates;
using Arctium.Protocol.Tls.Protocol.HandshakeProtocol.Enum;

namespace Arctium.Protocol.Tls.Protocol.HandshakeProtocol
{
    class Certificate : Handshake
    {
        public X509Certificate2[] ANS1Certificates;

        public Certificate(X509Certificate2[] cert)
        {
            base.MsgType = HandshakeType.Certificate;
            this.ANS1Certificates = cert;
        }
    }
}
