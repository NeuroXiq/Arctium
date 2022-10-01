using System;
using Arctium.Standards.Connection.Tls.Protocol.HandshakeProtocol;

namespace Arctium.Standards.Connection.Tls.Protocol.BinaryOps.Formatter.HandshakeFormatters
{
    class CertificateRequestFormatter : HandshakeFormatterBase
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