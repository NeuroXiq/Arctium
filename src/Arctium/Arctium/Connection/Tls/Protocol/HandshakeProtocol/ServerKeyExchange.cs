namespace Arctium.Connection.Tls.Protocol.HandshakeProtocol
{
    class ServerKeyExchange : Handshake
    {
        public ServerKeyExchange()
        {
            base.MsgType = HandshakeType.ServerKeyExchange;
        }
    }
}
