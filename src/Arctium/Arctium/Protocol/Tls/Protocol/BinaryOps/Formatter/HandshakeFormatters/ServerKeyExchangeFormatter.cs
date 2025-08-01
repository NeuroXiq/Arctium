using System;
using Arctium.Protocol.Tls.Protocol.HandshakeProtocol;

namespace Arctium.Protocol.Tls.Protocol.BinaryOps.Formatter.HandshakeFormatters
{
    class ServerKeyExchangeFormatter : HandshakeFormatterBase
    {
        public override int GetBytes(byte[] buffer, int offset, Handshake hs)
        {
            ServerKeyExchange skx = (ServerKeyExchange)hs;

            Buffer.BlockCopy(skx.KeyExchangeRawBytes, 0, buffer, offset, skx.KeyExchangeRawBytes.Length);

            return skx.KeyExchangeRawBytes.Length;
        }

        public override int GetLength(Handshake handshake)
        {
            ServerKeyExchange skx = (ServerKeyExchange)handshake;

            return skx.KeyExchangeRawBytes.Length;
        }
    }
}