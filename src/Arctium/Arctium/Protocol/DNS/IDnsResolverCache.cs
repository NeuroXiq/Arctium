using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNS
{
    public interface IDnsResolverCache
    {
        void SetDelegation(string hostName, object delegation);

        public void SetHostNameToIp(string hostName, IPAddress ip);
        
        public void SetIpToHostName(string hostName, IPAddress ip);
        
        public void SetAnswer(string hostName, object answer);

        public bool TryResolveHostNameToHostAddress(string hostName, out object result);

        public bool TryResolveHostAddressToHostName(IPAddress ipAddress, out object result);
        bool TryGetDelegation(string hostName, out IPAddress ipAddress);
        void CacheCname(string hostName, object response);
    }
}
