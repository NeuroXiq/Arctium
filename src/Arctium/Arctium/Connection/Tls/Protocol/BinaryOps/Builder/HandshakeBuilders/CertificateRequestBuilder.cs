using System;
using Arctium.Standards.Connection.Tls.Protocol.HandshakeProtocol;

namespace Arctium.Standards.Connection.Tls.Protocol.BinaryOps.Builder.HandshakeBuilders
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