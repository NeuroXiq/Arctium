﻿using Arctium.Protocol.Tls.Protocol.HandshakeProtocol.Enum;

namespace Arctium.Protocol.Tls.Protocol.HandshakeProtocol
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
