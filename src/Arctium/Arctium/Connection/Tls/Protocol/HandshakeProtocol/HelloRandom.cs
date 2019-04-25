namespace Arctium.Connection.Tls.Protocol.HandshakeProtocol
{

    class HelloRandom
    {
        public uint GmtUnixTime;
        public byte[] RandomBytes;

        public HelloRandom(uint unixTime, byte[] bytes)
        {
            GmtUnixTime = unixTime;
            RandomBytes = bytes;
        } 

    }
}
