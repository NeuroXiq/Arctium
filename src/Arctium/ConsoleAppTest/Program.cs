using Arctium.Protocol.DNS;
using Arctium.Protocol.DNSImpl.Protocol;

namespace Program
{
    class Program
    {
        static void Main(string[] args)
        {
            int q = int.Parse("-2147483648");
            Console.WriteLine("{0:X8}",(byte)((q)));
            Console.WriteLine("{0:X8}", ((int)-1));
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