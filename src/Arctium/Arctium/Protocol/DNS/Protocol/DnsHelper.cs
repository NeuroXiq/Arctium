namespace Arctium.Protocol.DNS.Protocol
{
    public class DnsHelper
    {
        public static bool DnsNameEquals(string name1, string name2)
        {
            if (name1 == name2) return true;
            if (name1 == null || name2 == null) return false;

            return string.Compare(name1, name2, true) == 0;
        }

        public static uint Ipv4ToUInt(string ipv4)
        {
            string[] parts = ipv4.Split('.');

            return
                uint.Parse(parts[0]) << 24 |
                uint.Parse(parts[1]) << 16 |
                uint.Parse(parts[2]) << 08 |
                uint.Parse(parts[3]) << 0;
        }
    }
}
