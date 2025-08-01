using System;
using Arctium.Protocol.Tls.Protocol.HandshakeProtocol;

namespace Arctium.Protocol.Tls.Protocol.BinaryOps.Formatter.HandshakeFormatters
{
    class ClientKeyExchangeFormatter : HandshakeFormatterBase
    {
        public ClientKeyExchangeFormatter() { }

        public override int GetBytes( byte[] buffer, int offset, Handshake handshakeMessage)
        {
            ClientKeyExchange kkx = (ClientKeyExchange)handshakeMessage;
            NumberConverter.FormatUInt16((ushort)kkx.KeyExchangeRawBytes.Length, buffer, offset);
            Buffer.BlockCopy(kkx.KeyExchangeRawBytes, 0, buffer, offset + 2, kkx.KeyExchangeRawBytes.Length);
            NumberConverter.FormatUInt16((ushort)kkx.KeyExchangeRawBytes.Length, buffer, offset);

            return kkx.KeyExchangeRawBytes.Length + 2;
        }

        public override int GetLength(Handshake handshake)
        {
            return ((ClientKeyExchange)handshake).KeyExchangeRawBytes.Length + 2;
        }
    }
}
