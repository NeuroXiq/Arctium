using Arctium.Protocol.DNS.Model;

namespace Arctium.Protocol.DNS
{
    public class DnsNode
    {
        public string Label { get; set; }
        public string Name { get; set; }
        public IList<ResourceRecord> Records { get; set; }
    }
}
