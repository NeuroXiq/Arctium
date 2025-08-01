using Arctium.Protocol.Tls.Protocol.HandshakeProtocol.Enum;

namespace Arctium.Protocol.Tls.Protocol.HandshakeProtocol
{
    class ClientKeyExchange : Handshake
    {
        ///<summary>Content of the Client key exchange message.
        ///Content is unpredictable and using this messages as a raw byte array is more easier.
        ///</summary>
        public byte[] KeyExchangeRawBytes;

        public ClientKeyExchange(byte[] exchangeKeyBytes)
        {
            KeyExchangeRawBytes = exchangeKeyBytes;
            base.MsgType = HandshakeType.ClientKeyExchange;
        }
    }
}
