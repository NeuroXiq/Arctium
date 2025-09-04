using Arctium.Protocol.DNS;
using Arctium.Protocol.DNSImpl.Model;
using Arctium.Protocol.DNSImpl.Protocol;
using System.Text;

namespace Program
{
    class Program
    {
        static void Main(string[] args)
        {
            int q = int.Parse("-2147483648");
            // DnsResolver c = new DnsResolver();

            var qq = Enum.GetNames<QType>();

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

        static byte[] bm = new byte[512];

        static readonly List<InMemRRData> records = new List<InMemRRData>()
        {
            // all-rrs stores all possible qtypes
            new InMemRRData("www.all-rrs.pl", QClass.IN, QType.A, "all-rrs-A", 111, new RDataA() { Address = 0x44332211 }),
            new InMemRRData("www.all-rrs.pl", QClass.IN, QType.NS, "all-rrs-NS", 1234, new RDataNS() { NSDName = "all-rrs-nsdname.pl" }),
            new InMemRRData("www.all-rrs.pl", QClass.IN, QType.MD, "all-rrs-MD", 1234, new RDataMD() { MADName = "www.all-rrs-mdname.pl" }),
            new InMemRRData("www.all-rrs.pl", QClass.IN, QType.MF, "all-rrs-MF", 1234, new RDataMF() { MADName = "www.all-rrs-mfname.pl" }),
            new InMemRRData("www.all-rrs.pl", QClass.IN, QType.CNAME, "all-rrs-CNAME", 1234, new RDataCNAME() { CName = "www.all-rrs-cname.pl" }),
            new InMemRRData("www.all-rrs.pl", QClass.IN, QType.SOA, "all-rrs-SOA", 1234, new RDataSOA()
            {
                Expire = 0x0000005,
                Minimum = 0x00000004,
                MName = "www.all-rrs-soa-mname.pl",
                Refresh = 0x00000006,
                Retry = 0x00000007,
                RName = "www.all-rrs-soa-rname.pl",
                Serial = 0x00000008
            }),
            new InMemRRData("www.all-rrs.pl", QClass.IN, QType.MB, "all-rrs-MB", 1234, new RDataMB() { MADName = "www.all-rrs-mb.pl" }),
            new InMemRRData("www.all-rrs.pl", QClass.IN, QType.MG, "all-rrs-MG", 1234, new RDataMG() { MGMName = "www.all-rrs-mg.pl" }),
            new InMemRRData("www.all-rrs.pl", QClass.IN, QType.MR, "all-rrs-MR", 433, new RDataMR() { NewName = "www.all-rrs-mr.pl" }),
            new InMemRRData("www.all-rrs.pl", QClass.IN, QType.NULL, "all-rrs-NULL", 1234, new RDataNULL()
            {
                //Anything = Encoding.ASCII.GetBytes("NULL Record - anything")
                Anything = new byte[] { 2, (byte)'a', (byte)'b', 0 }
            }),
            new InMemRRData("www.all-rrs.pl", QClass.IN, QType.WKS, "all-rrs-WKS", 1234, new RDataWKS()
            {
                Address = 0x7f000001,
                Bitmap = new byte[] { 0, 0, 0, (byte)((1 << 6)) }, // ok
                Protocol = 6
            }),
            new InMemRRData("www.all-rrs.pl", QClass.IN, QType.PTR, "all-rrs-PTR", 1234, new RDataPTR() { PtrDName = "www.all-rrs-ptr.pl" }),

            new InMemRRData("www.all-rrs.pl", QClass.IN, QType.HINFO, "all-rrs-HINFO", 1234,
            new RDataHINFO()
            {
                CPU = "www.all-rrs-cpu.pl", OS = "www.all-rrs-cpu.pl"
            }),
            new InMemRRData("www.all-rrs.pl", QClass.IN, QType.MINFO, "all-rrs-MINFO", 1234,
            new RDataMINFO()
            {
                EMailbx = "www.all-rrs-minfo-emailbx",
                RMailbx = "www.all-rrs-minfo-rmailbx"
            }),
            new InMemRRData("www.all-rrs.pl", QClass.IN, QType.MX, "all-rrs-MX", 1234, new RDataMX() { Preference = 5555, Exchange ="www.all-rrs-exchange"  }),
            new InMemRRData("www.all-rrs.pl", QClass.IN, QType.TXT, "all-rrs-TXT", 1234, new RDataTXT() { TxtData = new [] { "txt-line-1", "txt-line-2" } }),
        };
    }
}