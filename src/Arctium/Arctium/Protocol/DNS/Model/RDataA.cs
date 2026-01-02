using Arctium.Protocol.DNS.Protocol;

namespace Arctium.Protocol.DNS.Model
{
    /// <summary>
    /// </summary>
    public class RDataA
    {
        public uint Address;

        public RDataA() { }

        public RDataA(uint address)
        {
            Address = address;
        }

        public RDataA(string address)
        {
            Address = DnsSerialize.Ipv4ToUInt(address);
        }

        public override string ToString()
        {
            uint ipv4 = Address;
            return string.Format("{0}.{1}.{2}.{3}",
                (byte)(ipv4 >> 24),
                (byte)(ipv4 >> 16),
                (byte)(ipv4 >> 08),
                (byte)(ipv4 >> 00));
        }
    }
}
