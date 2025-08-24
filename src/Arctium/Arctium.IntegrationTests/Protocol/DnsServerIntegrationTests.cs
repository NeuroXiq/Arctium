using Arctium.Protocol.DNS;
using Arctium.Protocol.DNSImpl.Model;
using Newtonsoft.Json;
using System.Diagnostics;

namespace Arctium.IntegrationTests.Protocol
{
    [TestFixture]
    public class DnsServerIntegrationTests
    {
        DnsServer server;
        CancellationTokenSource serverStop;

        [OneTimeSetUp]
        public void OneTimeSetUp()
        {
            serverStop = new CancellationTokenSource();
            var cancellationToken = serverStop.Token;

            InMemoryDnsServerDataSource inMemDs = new InMemoryDnsServerDataSource();
            inMemDs.AddRange(records);
            DnsServerOptions options = new DnsServerOptions(inMemDs);
            server = new DnsServer(options);

            var task = Task.Run(() => { server.Start(cancellationToken); }, cancellationToken);

            for (int i = 0; i < 5 && task.Status != TaskStatus.Running; i++)
            {
                Task.Delay(500).Wait();
            }

            if (task.Status != TaskStatus.Running) throw new Exception("failed to run server task");
        }

        [OneTimeTearDown]
        public void OntTimeTearDown()
        {
            serverStop.Cancel();
            serverStop.Dispose();
        }

        [Test]
        public void Succeed_WillReturnAllRecordType()
        {
            // arrange

            var allValidQtypes = Enum.GetValues<QType>().Where(t => t != QType.All).ToArray();

            foreach (var qtype in allValidQtypes)
            {
                var result = QueryServer("www.all-rrs.pl", qtype);
                var expected = records.First(r => r.QName == "www.all-rrs.pl" && r.Record.Name == $"all-rrs-{qtype}" && r.Record.Type == qtype).Record;
                Assert.That(result.Count == 1);
                AssertRecordEqual(result[0], expected);
            }

            // assert
            Assert.IsTrue(false);
        }

        [Test]
        public void Succeed_ReturnRDataA_DomainNameWithDotAtTheEnd()
        {
            // arrange

            // act

            // assert
            Assert.IsTrue(false);
        }

        [Test]
        public void Succeed_ReturnRDataA_DomainNameWithoutDotAtTheEnd()
        {
            // arrange

            // act

            // assert
            Assert.IsTrue(false);
        }

        [Test]
        public void WillReturnRecordWithMinDomainName()
        {
            // arrange

            // act

            // assert
            Assert.IsTrue(false);
        }

        [Test]
        public void WillReturnRecordWithMaxDomainName()
        {
            // arrange

            // act

            // assert
            Assert.IsTrue(false);
        }


        const string www_test_pl = "www.test.pl";
        const string www_google1_pl = "www.google1.pl";

        // all tests runs under single server with these records
        // all record current server have
        static readonly List<InMemRRData> records = new List<InMemRRData>()
        {
            new InMemRRData("www.all-rrs.pl", QClass.IN, QType.A, "all-rrs-A", 111, new RDataA() { Address = 0x44332211 }),
            // new InMemRRData("www.all-rrs.pl", QClass.IN, QType.NS, "all-rrs-NS", 1234, new RDataNS(),
            // new InMemRRData("www.all-rrs.pl", QClass.IN, QType.MD, "all-rrs-MD", 1234, new RDataMD(),
            // new InMemRRData("www.all-rrs.pl", QClass.IN, QType.MF, "all-rrs-MF", 1234, new RDataMF(),
            // new InMemRRData("www.all-rrs.pl", QClass.IN, QType.CNAME, "all-rrs-CNAME", 1234, new RDataCNAME(),
            // new InMemRRData("www.all-rrs.pl", QClass.IN, QType.SOA, "all-rrs-SOA", 1234, new RDataSOA(),
            // new InMemRRData("www.all-rrs.pl", QClass.IN, QType.MB, "all-rrs-MB", 1234, new RDataMB(),
            // new InMemRRData("www.all-rrs.pl", QClass.IN, QType.MG, "all-rrs-MG", 1234, new RDataMG(),
            // new InMemRRData("www.all-rrs.pl", QClass.IN, QType.MR, "all-rrs-MR", 1234, new RDataMR(),
            // new InMemRRData("www.all-rrs.pl", QClass.IN, QType.NULL, "all-rrs-NULL", 1234, new RDataNULL(),
            // new InMemRRData("www.all-rrs.pl", QClass.IN, QType.WKS, "all-rrs-WKS", 1234, new RDataWKS(),
            // new InMemRRData("www.all-rrs.pl", QClass.IN, QType.PTR, "all-rrs-PTR", 1234, new RDataPTR(),
            // new InMemRRData("www.all-rrs.pl", QClass.IN, QType.HINFO, "all-rrs-HINFO", 1234, new RDataHINFO(),
            // new InMemRRData("www.all-rrs.pl", QClass.IN, QType.MINFO, "all-rrs-MINFO", 1234, new RDataMINFO(),
            // new InMemRRData("www.all-rrs.pl", QClass.IN, QType.MX, "all-rrs-MX", 1234, new RDataMX(),
            new InMemRRData("www.all-rrs.pl", QClass.IN, QType.TXT, "all-rrs-TXT", 1234, new RDataTXT() { TxtData = "test-txt-data" }),
            // new InMemRRData("www.all-rrs.pl", QClass.IN, QType.AXFR, "all-rrs-AXFR", 1234, new RDataAXFR(),
            // new InMemRRData("www.all-rrs.pl", QClass.IN, QType.MAILB, "all-rrs-MAILB", 1234, new RDataMAILB(),
            // new InMemRRData("www.all-rrs.pl", QClass.IN, QType.MAILA, "all-rrs-MAILA", 1234, new RDataMAILA(),
            // new InMemRRData("www.all-rrs.pl", QClass.IN, QType.All, "all-rrs-All", 1234, new RDataAll(),

            new InMemRRData("www.test.pl", QClass.IN, QType.A, "testplname", 111, new RDataA() { Address = 0x44332211 }),
            new InMemRRData("www.test.pl", QClass.IN, QType.A, "testplname", 111, new RDataA() { Address = 0x44332211 }),
            new InMemRRData("www.test.pl", QClass.HS, QType.A, "testplname", 111, new RDataA() { Address = 0x44332211 }),
            new InMemRRData("www.test.pl", QClass.CS, QType.A, "testplname", 111, new RDataA() { Address = 0x44332211 }),
            new InMemRRData("www.test.pl", QClass.CH, QType.A, "testplname", 111, new RDataA() { Address = 0x44332211 }),

            new InMemRRData("www.google1.pl", QClass.IN, QType.A, "testplname", 111, new RDataA() { Address = 0x44332211 })
        };

        private static void AssertRecordEqual(PwshRecord current, ResourceRecord expected)
        {
            Assert.IsTrue(
                current.TTL == expected.TTL &&
                expected.Name == current.Name &&
                (int)expected.Type == current.Type,
                "expected != current");

            switch (expected.Type)
            {
                case QType.A:
                    Assert.That(int.Parse(current.IP4Address) == (expected.RData as RDataA).Address);
                    break;
                case QType.All:
                    Assert.IsTrue(false, "must never happen - invalid expected type"); // must never happen
                    break;
                default:
                    throw new NotImplementedException("todo implement other QType conditions");
            }


            throw new NotImplementedException();
        }

        private List<PwshRecord> QueryServer(string domainName, QType qtype)
        {
            ProcessStartInfo startInfo = new ProcessStartInfo();
            startInfo.FileName = @"powershell.exe";
            startInfo.Arguments = $@"-command convertto-json @(resolve-dnsname {domainName} -server 127.0.0.1 -type {qtype})";
            startInfo.RedirectStandardOutput = true;
            startInfo.RedirectStandardError = true;
            startInfo.UseShellExecute = false;
            startInfo.CreateNoWindow = true;
            Process process = new Process();
            process.StartInfo = startInfo;
            process.Start();

            string pwshJsonOutput = process.StandardOutput.ReadToEnd();
            var result = JsonConvert.DeserializeObject<List<PwshRecord>>(pwshJsonOutput);

            string errors = process.StandardError.ReadToEnd();
            Assert.IsTrue(string.IsNullOrEmpty(errors));

            return result;
        }

        class PwshRecord
        {
            public string IP6Address { get; set; }
            public string IP4Address { get; set; }
            public string Name { get; set; }
            public int Type { get; set; }
            public int CharacterSet { get; set; }
            public int Section { get; set; }
            public int DataLength { get; set; }
            public int TTL { get; set; }
            public string Address { get; set; }
            public string IPAddress { get; set; }
            public int QueryType { get; set; }
        }

        static DnsServerIntegrationTests()
        {
        }
    }
}


/*
         this is example output from powershell
[
    {
        "IP6Address":  "2a00:1450:401b:80d::2004",
        "Name":  "www.google.com",
        "Type":  28,
        "CharacterSet":  1,
        "Section":  1,
        "DataLength":  16,
        "TTL":  44,
        "Address":  "2a00:1450:401b:80d::2004",
        "IPAddress":  "2a00:1450:401b:80d::2004",
        "QueryType":  28
    },
    {
        "IP4Address":  "142.250.186.196",
        "Name":  "www.google.com",
        "Type":  1,
        "CharacterSet":  1,
        "Section":  1,
        "DataLength":  4,
        "TTL":  30,
        "Address":  "142.250.186.196",
        "IPAddress":  "142.250.186.196",
        "QueryType":  1
        }

]
         */
