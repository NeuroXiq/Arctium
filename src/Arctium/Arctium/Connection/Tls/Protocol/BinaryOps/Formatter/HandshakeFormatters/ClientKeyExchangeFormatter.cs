using System;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;

namespace Arctium.Connection.Tls.Protocol.BinaryOps.Formatter.HandshakeFormatters
{
    class ClientKeyExchangeFormatter : HandshakeFormatterBase
    {
        public ClientKeyExchangeFormatter() { }

        public override void FormatBytes(Handshake hs, byte[] buffer, int offset)
        {
            ClientKeyExchange kkx = (ClientKeyExchange)hs;
            NumberConverter.FormatUInt16((ushort)kkx.ExchangeKeys.Length, buffer, offset);
            Buffer.BlockCopy(kkx.ExchangeKeys, 0, buffer, offset + 2, kkx.ExchangeKeys.Length);
        }

        public override int GetLength(Handshake handshake)
        {
            return ((ClientKeyExchange)handshake).ExchangeKeys.Length + 2;
        }
    }
}
