using Arctium.Protocol.DNS;
using Arctium.Protocol.DNSImpl.Protocol;

namespace Program
{
    class Program
    {
        static void Main(string[] args)
        {
            // DnsResolver c = new DnsResolver();
            dnsserver();
        }

        static void dnsserver()
        {
            DnsServerImpl dnsserver = new DnsServerImpl(null);
            dnsserver.Start();

        }
    }
}