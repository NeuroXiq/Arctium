using System;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;

namespace Arctium.Connection.Tls.Protocol.BinaryOps.Formatter.HandshakeFormatters
{
    class ServerKeyExchangeFormatter : HandshakeFormatterBase
    {
        public override int GetBytes(byte[] buffer, int offset, Handshake hs)
        {
            ServerKeyExchange skx = (ServerKeyExchange)hs;

            Buffer.BlockCopy(skx.KeyExchangeParams, 0, buffer, offset, skx.KeyExchangeParams.Length);
            Buffer.BlockCopy(skx.ParamsSignature, 0, buffer, offset + skx.KeyExchangeParams.Length, skx.ParamsSignature.Length);

            return skx.ParamsSignature.Length + skx.KeyExchangeParams.Length;
        }

        public override int GetLength(Handshake handshake)
        {
            ServerKeyExchange skx = (ServerKeyExchange)handshake;

            return skx.ParamsSignature.Length + skx.KeyExchangeParams.Length;
        }
    }
}