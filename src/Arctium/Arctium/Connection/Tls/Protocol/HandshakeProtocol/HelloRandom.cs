using Arctium.Connection.Tls.Protocol.BinaryOps;
using System;

namespace Arctium.Connection.Tls.Protocol.HandshakeProtocol
{

    class HelloRandom
    {
        public uint GmtUnixTime;
        public byte[] RandomBytes;
        public byte[] RawBytes;

        public HelloRandom(uint unixTime, byte[] bytes)
        {
            GmtUnixTime = unixTime;
            RandomBytes = bytes;

            RawBytes = new byte[4 + bytes.Length];
            NumberConverter.FormatUInt32(unixTime, RawBytes, 0);
            Array.Copy(bytes, 0, RawBytes, 4, bytes.Length);
        } 

    }
}
