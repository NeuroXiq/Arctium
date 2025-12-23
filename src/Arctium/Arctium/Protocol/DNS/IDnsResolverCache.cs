using Arctium.Protocol.DNS.Model;

namespace Arctium.Protocol.DNS
{
    public interface IDnsResolverCache
    {
        bool TryGet(string hostName, QClass qclass, QType qtype, out ResourceRecord[] resultResourceRecords);

        void Set(ResourceRecord[] resourceRecords);
    }
}
