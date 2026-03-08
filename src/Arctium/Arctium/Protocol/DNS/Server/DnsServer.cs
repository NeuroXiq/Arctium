using Arctium.Protocol.DNS.Protocol;

namespace Arctium.Protocol.DNS.Server
{
    public class DnsServer
    {
        DnsServerImpl dnsServerImpl;

        public DnsServer(DnsServerOptions options)
        {
            dnsServerImpl = new DnsServerImpl(options);
        }

        public void StartUdp() => dnsServerImpl.StartUdp();
        public void StartTcp() => dnsServerImpl.StartTcp();

        public void Start();
        public void Stop();
    }
}
