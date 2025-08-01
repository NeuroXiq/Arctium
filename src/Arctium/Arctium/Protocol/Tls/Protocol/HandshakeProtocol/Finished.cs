﻿using Arctium.Protocol.Tls.Protocol.HandshakeProtocol.Enum;

namespace Arctium.Protocol.Tls.Protocol.HandshakeProtocol
{
    class Finished : Handshake
    {
        public byte[] VerifyData;

        public Finished(byte[] verifyData)
        {
            MsgType = HandshakeType.Finished;
            VerifyData = verifyData;
        }
    }
}
