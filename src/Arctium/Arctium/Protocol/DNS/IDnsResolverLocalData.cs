using Arctium.Protocol.DNS.Model;

namespace Arctium.Protocol.DNS
{
    public interface IDndResolverLocalData
    {
        ResourceRecord[] SBeltServers { get; }

        bool TryGetCache(string hostName, QClass qclass, QType qtype,  out ResourceRecord[] resultResourceRecords);

        void AddCache(ResourceRecord[] resourceRecords);
    }
}
