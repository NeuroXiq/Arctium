namespace Arctium.Protocol.Tls.Protocol
{
    public struct ProtocolVersion
    {
        public byte Major;
        public byte Minor;

        public ProtocolVersion(byte major, byte minor)
        {
            Major = major;
            Minor = minor;
        }
    }
}
