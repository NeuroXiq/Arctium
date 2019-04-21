using System;

namespace Arctium.Connection.Tls.HandshakeProtocol
{
    class Handshake
    {
        public HandshakeType MsgType { get; private set; }
        ushort Length;
    }
}
