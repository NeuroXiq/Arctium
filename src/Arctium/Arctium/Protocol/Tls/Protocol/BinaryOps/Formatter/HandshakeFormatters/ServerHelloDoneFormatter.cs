using System;
using Arctium.Protocol.Tls.Protocol.HandshakeProtocol;

namespace Arctium.Protocol.Tls.Protocol.BinaryOps.Formatter.HandshakeFormatters
{
    class ServerHelloDoneFormatter : HandshakeFormatterBase
    {
        public ServerHelloDoneFormatter() { }

        public override int GetBytes( byte[] buffer, int offset, Handshake handshakeMessage)
        {
            return 0;
        }

        public byte[] GetBytes(ServerHelloDone serverHelloDone)
        {
            return new byte[0];
        }

        public override int GetLength(Handshake handshake)
        {
            return 0;
        }
    }
}
