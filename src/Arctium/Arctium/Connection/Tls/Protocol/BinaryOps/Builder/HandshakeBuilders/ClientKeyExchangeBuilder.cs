using System;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;

namespace Arctium.Connection.Tls.Protocol.BinaryOps.Builder.HandshakeBuilders
{
    internal class ClientKeyExchangeBuilder : HandshakeBuilderBase
    {
        public override Handshake BuildFromBytes(byte[] buffer, int offset, int length)
        {
            ClientKeyExchange keyExchange = new ClientKeyExchange();
            keyExchange.MsgType = HandshakeType.ClientKeyExchange;
            int encryptedBytesVectorLength = NumberConverter.ToUInt16(buffer, offset);

            int delta = encryptedBytesVectorLength - length + 2;
            if (delta != 0)
            {
                if (delta > 0) throw new MessageFromatException("Invalid length of vector of ClientKeyExchange encrypted data. Vector is larger than content length");
                else throw new MessageFromatException("Invalid length of vector of ClientKeyExchange encrypted data. Vector is smaller than content length");
            }

            int encryptedBytesOffset = offset + 2;

            keyExchange.ExchangeKeys = new byte[encryptedBytesVectorLength];
            Array.Copy(buffer, encryptedBytesOffset, keyExchange.ExchangeKeys, 0, encryptedBytesVectorLength);

            return keyExchange;
        }
    }
}