namespace Arctium.Connection.Tls.Protocol.HandshakeProtocol
{
    class ClientKeyExchange : Handshake
    {
        public byte[] ExchangeKeys;

        public ClientKeyExchange()
        {
            base.MsgType = HandshakeType.ClientKeyExchange;
        }
    }
}
