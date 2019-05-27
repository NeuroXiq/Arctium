using System;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;

namespace Arctium.Connection.Tls.Protocol.BinaryOps.Formatter.HandshakeFormatters
{
    class ClientKeyExchangeFormatter : HandshakeFormatterBase
    {
        public ClientKeyExchangeFormatter() { }

        public override int GetBytes( byte[] buffer, int offset, Handshake handshakeMessage)
        {
            ClientKeyExchange kkx = (ClientKeyExchange)handshakeMessage;
            NumberConverter.FormatUInt16((ushort)kkx.ExchangeKeys.Length, buffer, offset);
            Buffer.BlockCopy(kkx.ExchangeKeys, 0, buffer, offset + 2, kkx.ExchangeKeys.Length);

            return kkx.ExchangeKeys.Length;
        }

        public override int GetLength(Handshake handshake)
        {
            return ((ClientKeyExchange)handshake).ExchangeKeys.Length + 2;
        }
    }
}
