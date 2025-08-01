using System;
using Arctium.Protocol.Tls.Protocol.HandshakeProtocol;

namespace Arctium.Protocol.Tls.Protocol.BinaryOps.Builder.HandshakeBuilders
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