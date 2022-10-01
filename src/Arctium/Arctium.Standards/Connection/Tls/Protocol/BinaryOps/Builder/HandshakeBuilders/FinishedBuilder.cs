using System;
using Arctium.Standards.Connection.Tls.Protocol.HandshakeProtocol;

namespace Arctium.Standards.Connection.Tls.Protocol.BinaryOps.Builder.HandshakeBuilders
{
    internal class FinishedBuilder : HandshakeBuilderBase
    {
        public override Handshake BuildFromBytes(byte[] buffer, int offset, int length)
        {
            byte[] verifyData = new byte[length];
            Buffer.BlockCopy(buffer, offset, verifyData, 0, length);

            Finished finished = new Finished(verifyData);

            return finished;
        }
    }
}