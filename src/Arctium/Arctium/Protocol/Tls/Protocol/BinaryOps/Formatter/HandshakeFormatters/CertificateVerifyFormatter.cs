using System;
using Arctium.Protocol.Tls.Protocol.HandshakeProtocol;

namespace Arctium.Protocol.Tls.Protocol.BinaryOps.Formatter.HandshakeFormatters
{
    class CertificateVerifyFormatter : HandshakeFormatterBase
    {
        public override int GetBytes( byte[] buffer, int offset, Handshake handshakeMessage)
        {
            throw new NotImplementedException();
        }

        public override int GetLength(Handshake handshake)
        {
            throw new NotImplementedException();
        }
    }
}