using System;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;

namespace Arctium.Connection.Tls.Protocol.BinaryOps.Builder.HandshakeBuilders
{
    internal class CertificateRequestBuilder : HandshakeBuilderBase
    {
        public CertificateRequestBuilder()
        {
        }

        public override Handshake BuildFromBytes(byte[] buffer, int offset, int length)
        {
            throw new NotImplementedException();
        }
    }
}