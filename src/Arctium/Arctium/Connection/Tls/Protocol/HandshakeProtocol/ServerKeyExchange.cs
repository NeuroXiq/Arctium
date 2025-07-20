namespace Arctium.Standards.Connection.Tls.Protocol.HandshakeProtocol
{
    class ServerKeyExchange : Handshake
    {
        public byte[] KeyExchangeRawBytes;

        public ServerKeyExchange()
        {
            base.MsgType = HandshakeType.ServerKeyExchange;
        }
    }
}
