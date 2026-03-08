namespace Arctium.Protocol.DNS.Server
{
    public class DnsServer
    {
        DnsServerImpl dnsServerImpl;

        public DnsServer(DnsServerOptions options)
        {
            dnsServerImpl = new DnsServerImpl(options);
        }


        public void Start() => dnsServerImpl.Start();
        public void Stop() => dnsServerImpl.Stop();
    }
}
