using Arctium.Protocol.DNS.Model;

namespace Arctium.Protocol.DNS
{
    public interface IDndResolverLocalData
    {
        //void SetDelegation(string hostName, object delegation);

        //public void SetHostNameToIp(string hostName, IPAddress ip);

        //public void SetIpToHostName(string hostName, IPAddress ip);

        //public void SetAnswer(string hostName, object answer);

        //public bool TryResolveHostNameToHostAddress(string hostName, out object result);

        //public bool TryResolveHostAddressToHostName(IPAddress ipAddress, out object result);
        //bool TryGetDelegation(string hostName, out IPAddress ipAddress);
        //void CacheCname(string hostName, object response);

        ResourceRecord[] GetSBeltServers();

        bool TryGetCache(string hostName, QType qtype, QClass qclass, out ResourceRecord[] resultResourceRecords);

        void AppendCache(ResourceRecord[] resourceRecords);
    }
}
