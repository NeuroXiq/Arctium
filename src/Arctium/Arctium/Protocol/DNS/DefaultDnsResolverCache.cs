using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNS
{
    public class DefaultDnsResolverCache : IDnsResolverCache
    {

        public string ResolveHostAddressToHostName(IPAddress ipAddress)
        {
            throw new NotImplementedException();
        }

        public IPAddress ResolveHostNameToHostAddress(string hostName)
        {
            throw new NotImplementedException();
        }

        public void SetHostNameToIp(string hostName, IPAddress ip)
        {
            throw new NotImplementedException();
        }

        public void SetIpToHostName(string hostName, IPAddress ip)
        {
            throw new NotImplementedException();
        }

        public string TryResolveHostAddressToHostName(IPAddress ipAddress)
        {
            throw new NotImplementedException();
        }

        public object TryResolveHostNameToHostAddress(string hostName, out bool success)
        {
            throw new NotImplementedException();
        }
    }
}
