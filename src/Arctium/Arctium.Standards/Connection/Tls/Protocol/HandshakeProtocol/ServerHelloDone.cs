namespace Arctium.Standards.Connection.Tls.Protocol.HandshakeProtocol
{
    class ServerHelloDone : Handshake
    {
        public ServerHelloDone()
        {
            base.MsgType = HandshakeType.ServerHelloDone;
        }
    }
}
