namespace Arctium.Connection.Tls.Protocol
{
    public struct ProtocolVersion
    {
        byte Major;
        byte Minor;

        public ProtocolVersion(byte major, byte minor)
        {
            Major = major;
            Minor = minor;
        }
    }
}
