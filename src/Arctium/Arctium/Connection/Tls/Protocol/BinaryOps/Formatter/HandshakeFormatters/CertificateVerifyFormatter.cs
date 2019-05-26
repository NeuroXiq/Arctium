using System;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;

namespace Arctium.Connection.Tls.Protocol.BinaryOps.Formatter.HandshakeFormatters
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