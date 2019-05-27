namespace Arctium.Connection.Tls.Protocol.HandshakeProtocol
{
    class ClientKeyExchange : Handshake
    {
        public byte[] ExchangeKeys;

        public ClientKeyExchange(byte[] exchangeKeyBytes)
        {
            ExchangeKeys = exchangeKeyBytes;
            base.MsgType = HandshakeType.ClientKeyExchange;
        }
    }
}
