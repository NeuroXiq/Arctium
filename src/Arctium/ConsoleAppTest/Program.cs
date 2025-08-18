using Arctium.Protocol.DNS;
using Arctium.Protocol.DNSImpl.Protocol;

namespace Program
{
    class Program
    {
        static void Main(string[] args)
        {
            int q = int.Parse("-2147483648");
            // DnsResolver c = new DnsResolver();
            dnsserver();
        }

        static void dnsserver()
        {
            DnsServerImpl dnsserver = new DnsServerImpl(null);
            dnsserver.Start();
            Console.Read();
        }
    }
}