using Arctium.Protocol.Tls.Protocol.HandshakeProtocol.Enum;

namespace Arctium.Protocol.Tls.Protocol.HandshakeProtocol
{
    class ServerHelloDone : Handshake
    {
        public ServerHelloDone()
        {
            base.MsgType = HandshakeType.ServerHelloDone;
        }
    }
}
