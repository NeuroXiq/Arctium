namespace Arctium.Protocol.DNS.Model
{
    public class RDataAAAA
    {
        /// <summary>
        /// 128-bit ipv6 address in network-byte order
        /// </summary>
        public byte[] IPv6;

        public RDataAAAA() { }
        public RDataAAAA(byte[] ipv6) { IPv6 = ipv6; }
    }
}
