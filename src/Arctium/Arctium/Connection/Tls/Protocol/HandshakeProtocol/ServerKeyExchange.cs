namespace Arctium.Connection.Tls.Protocol.HandshakeProtocol
{
    class ServerKeyExchange : Handshake
    {
        public byte[] KeyExchangeParams;
        public byte[] ParamsSignature;

        public ServerKeyExchange()
        {
            base.MsgType = HandshakeType.ServerKeyExchange;
        }
    }
}
