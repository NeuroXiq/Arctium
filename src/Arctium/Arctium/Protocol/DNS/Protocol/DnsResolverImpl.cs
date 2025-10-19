using Arctium.Protocol.DNS;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNS.Protocol
{
    public class DnsResolverImpl
    {
        private DnsResolverOptions options;
        private IDnsResolverCache cache { get { return options.Cache; } }

        public DnsResolverImpl(DnsResolverOptions options)
        {
            this.options = options;
        }

        internal void ResolveGeneralLookupFunction()
        {
            throw new NotImplementedException();
        }

        internal void ResolveHostAddressToHostName(IPAddress ipAddress)
        {
            throw new NotImplementedException();
        }

        internal object ResolveHostNameToHostAddress(string hostName)
        {
            step1:
            // RFC-1035 5.3.3. Algorithm 
            // 1. check cache

            if (options.UseCache && options.Cache != null && options.Cache.TryResolveHostNameToHostAddress(hostName, out var result))
            {
                return result;
            }

            List<IPAddress> toSkip = new List<IPAddress>();

            step2:
            // 2. find best servers to ask
            var dnsServerIp = FindBestServersToAsk(hostName, toSkip);

            try
            {
                var response = SendRequestToDnsServer(new object(), dnsServerIp);

                // if response resolved ok or name error cache result
                if (response != null /* if response*/)
                {
                    cache.SetAnswer(hostName, response);

                    return response;
                }

                // if response delegation to other server:
                if (true)
                {
                    cache.SetDelegation(hostName, response);
                    goto step2;
                }

                // if response is CNAME and is not an answer
                if (true)
                {
                    cache.CacheCname(hostName, response);
                    // change sname to canonical name and go to step 1
                    goto step1;
                }

                // if server failure or bizzare content skip this server
                if (true)
                {
                    toSkip.Add(dnsServerIp);
                }
            }
            catch (Exception e)
            {
                // what if no internet connection?

                toSkip.Add(dnsServerIp);
            }

            throw new NotImplementedException();
        }

        private IPAddress FindBestServersToAsk(string hostName, IList<IPAddress> ignoreServers)
        {
            if (options.Cache.TryGetDelegation(hostName, out var ipAddress))
            {
                return ipAddress;
            }

            var fromOptions = options.DnsServers?.FirstOrDefault(x => !ignoreServers.Any(toSkip => toSkip.Equals(x)));

            if (fromOptions != null)
            {
                return fromOptions;
            }

            var fromRootServers = DnsRootServers.All.FirstOrDefault(x => !ignoreServers.Any(toSkip => toSkip.Equals(x)))?.IPv4Address;

            if (fromRootServers != null)
            {
                return fromRootServers;
            }

            throw new DnsException(DnsProtocolError.CannotFindDnsServerToAsk, "Cannot find DNS server to ask");
        }

        object SendRequestToDnsServer(object something, IPAddress dnsServerIp)
        {
            return null;
        }
    }
}
