using System;
using Arctium.Standards.Connection.Tls.Protocol.HandshakeProtocol;

namespace Arctium.Standards.Connection.Tls.Protocol.BinaryOps.Builder.HandshakeBuilders
{
    internal class ClientKeyExchangeBuilder : HandshakeBuilderBase
    {
        public override Handshake BuildFromBytes(byte[] buffer, int offset, int length)
        {

            byte[] exchangeKeysBytes = new byte[length];
            Buffer.BlockCopy(buffer, offset, exchangeKeysBytes, 0, length);

            ClientKeyExchange keyExchange = new ClientKeyExchange(exchangeKeysBytes);

            return keyExchange;
        }
    }
}