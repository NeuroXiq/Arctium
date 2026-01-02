namespace Arctium.Protocol.DNS.Model
{
    public class RDataAAAA
    {
        /// <summary>
        /// 128-bit ipv6 address in network-byte order.
        /// </summary>
        public byte[] IPv6;

        public RDataAAAA() { }
        public RDataAAAA(byte[] ipv6) { IPv6 = ipv6; }

        public override string ToString()
        {
            if (IPv6 == null) return "NULL";
            if (IPv6.Length != 16) return $"<invalid ip != 16 length>: " + string.Join(", ", IPv6.Select(t => $"{t:X2}").ToArray());

            return new System.Net.IPAddress(IPv6).ToString();
        }
    }
}
