using Arctium.Protocol.DNS.Model;

namespace Arctium.Protocol.DNS
{
    public interface IDndResolverLocalData
    {
        ResourceRecord[] SBeltServers { get; }

        IDnsResolverCache Cache { get; }
    }
}
