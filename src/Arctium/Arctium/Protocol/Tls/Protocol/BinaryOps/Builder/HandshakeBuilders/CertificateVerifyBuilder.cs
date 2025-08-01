using System;
using Arctium.Protocol.Tls.Protocol.HandshakeProtocol;

namespace Arctium.Protocol.Tls.Protocol.BinaryOps.Builder.HandshakeBuilders
{
    internal class CertificateVerifyBuilder : HandshakeBuilderBase
    {
        public override Handshake BuildFromBytes(byte[] buffer, int offset, int length)
        {
            throw new NotImplementedException();
        }
    }
}