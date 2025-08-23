using Arctium.Protocol.DNS;
using Arctium.Protocol.DNSImpl.Model;
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
            var ds = new InMemoryDnsServerDataSource();
            ds.Add(new InMemRRData("www.google.com", QClass.IN, QType.A, "namew1", 1234, new RDataA() { Address = 0x05040302 }));

            var options = new DnsServerOptions(ds);

            DnsServerImpl dnsserver = new DnsServerImpl(options);
            dnsserver.Start(default);
            Console.Read();
        }
    }
}