using Arctium.Connection.Tls.Protocol.HandshakeProtocol;

namespace Arctium.Connection.Tls.Protocol.BinaryOps.Formatter.HandshakeFormatters
{
    class ServerHelloDoneFormatter
    {
        public ServerHelloDoneFormatter() { }

        public byte[] GetBytes(ServerHelloDone serverHelloDone)
        {
            return new byte[0];
        }
    }
}
