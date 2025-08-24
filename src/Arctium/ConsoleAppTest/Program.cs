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

            var qq = Enum.GetNames<QType>();

            foreach (var qt in qq)
            {
                Console.WriteLine($"// new InMemRRData(\"www.all-rrs.pl\", QClass.IN, QType.{qt}, \"all-rrs-{qt}\", 1234, new RData{qt}(),");
            }

            dnsserver();
        }

        static void dnsserver()
        {
            var ds = new InMemoryDnsServerDataSource();
            ds.AddRange(records);

            var options = new DnsServerOptions(ds);

            DnsServerImpl dnsserver = new DnsServerImpl(options);
            dnsserver.Start(default);
            Console.Read();
        }

        static readonly List<InMemRRData> records = new List<InMemRRData>()
        {
            new InMemRRData("www.test.pl", QClass.IN, QType.A, "testplname", 111, new RDataA() { Address = 0x44332211 }),
            new InMemRRData("www.test.pl", QClass.IN, QType.A, "testplname", 111, new RDataA() { Address = 0x54332211 }),
            new InMemRRData("www.test.pl", QClass.HS, QType.A, "testplname", 111, new RDataA() { Address = 0x44332211 }),
            new InMemRRData("www.test.pl", QClass.CS, QType.A, "testplname", 111, new RDataA() { Address = 0x44332211 }),
            new InMemRRData("www.test.bind", QClass.CH, QType.A, "testplname", 111, new RDataA() { Address = 0x44332211 }),

            new InMemRRData("www.google1.pl", QClass.IN, QType.A, "testplname", 111, new RDataA() { Address = 0x44332211 })
        };
    }
}