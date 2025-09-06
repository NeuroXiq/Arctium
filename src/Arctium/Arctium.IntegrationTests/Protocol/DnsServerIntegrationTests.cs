using Arctium.Protocol.DNS;
using Arctium.Protocol.DNSImpl.Model;
using Arctium.Protocol.DNSImpl.Protocol;
using Newtonsoft.Json;
using System.Diagnostics;
using System.Net;
using System.Text;

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
            DnsServerOptions options = DnsServerOptions.CreateDefault(inMemDs, cancellationToken);
            server = new DnsServer(options);

            var taskUdp = Task.Run(() => { server.StartUdp(); }, cancellationToken);
            var taskTcp = Task.Run(() => { server.StartTcp(); }, cancellationToken);

            for (int i = 0; i < 5 && taskUdp.Status != TaskStatus.Running && taskTcp.Status != TaskStatus.Running; i++)
            {
                Task.Delay(500).Wait();
            }

            if (taskUdp.Status != TaskStatus.Running || taskTcp.Status != TaskStatus.Running) throw new Exception("failed to run server task");
        }

        [OneTimeTearDown]
        public void OntTimeTearDown()
        {
            serverStop.Cancel();
            serverStop.Dispose();
        }


        [Test]
        public void Succees_WillWorkTcpWithLargeAmountOfTxtData()
        {
            // arrange
            var expectedRows = records.Where(t => t.QName == "www.tcp-large-data.pl").ToList();

            // act
            var result = QueryServer("www.tcp-large-data.pl", QType.TXT);

            // assert
            Assert.That(expectedRows.Count == result.Count);
            expectedRows.ForEach(e =>
            {
                var expected = e.Record;
                var current = result.Single(r => r.Text.Contains(((RDataTXT)expected.RData).TxtData[0]));
                AssertRecordEqual(current, expected);
            });
        }


        [Test]
        public void Succeed_WillAcceptMultipleParallelClients()
        {
            // arrange & act
            var tasks = Enumerable.Range(0, 50)
                .Select(t => Task.Factory.StartNew(() => { QueryServer("www.multiple-parralel", QType.A); }))
                .ToArray();

            Task.WaitAny(Task.WhenAll(tasks), Task.Delay(10000));

            // assert
            Assert.IsTrue(tasks.All(t => t.IsCompletedSuccessfully));
        }

        [Test]
        public void Success_WillTruncateResponse()
        {
            // arrange

            // act

            // assert
            Assert.IsTrue(false);
        }

        [Test]
        public void Succeed_WillReturnAllRecordType()
        {
            // arrange

            var allValidQtypes = Enum.GetValues<QType>()
                .Where(t =>
                t != QType.NULL &&
                t != QType.All &&
                t != QType.AXFR &&
                t != QType.MAILA &&
                t != QType.MAILB)
                .ToArray();

            // act

            foreach (var qtype in allValidQtypes)
            {
                var result = QueryServer("www.all-rrs.pl", qtype);
                var expected = records.First(r => r.QName == "www.all-rrs.pl" && r.Record.Name == $"all-rrs-{qtype}" && r.Record.Type == qtype).Record;
                Assert.That(result.Count == 1);
                
                // assert
                AssertRecordEqual(result[0], expected);
            }
        }

        [Test]
        public void Succeed_WhenExceed512BytesWillReturnTrunCated()
        {
            // arrange
            var expected = records.Single(t => t.QName == "www.exceed-512-bytes.pl").Record;

            // act
            var current = QueryServer("www.exceed-512-bytes.pl", QType.TXT).Single();

            // assert
            AssertRecordEqual(current, expected);
        }

        [Test]
        public void Succeed_ReturnRDataA_DomainNameWithDotAtTheEnd()
        {
            // act
            var current = QueryServer("www.domain-with-dot.pl.", QType.A).Single();
            var expected = records.Single(t => t.QName == "www.domain-with-dot.pl.").Record;

            // assert
            AssertRecordEqual(current, expected);
        }

        [Test]
        public void Succeed_ReturnRDataA_DomainNameWithoutDotAtTheEnd()
        {
            // act
            var current = QueryServer("www.domain-with-no-dot-at-the-end.pl", QType.A);

            // assert
            AssertRecordEqual(current.Single(), records.Single(t => t.QName == "www.domain-with-no-dot-at-the-end.pl").Record);
        }

        [Test]
        public void WillReturnRecordWithMinDomainName()
        {
            // act
            var current = QueryServer("a.", QType.A);

            // assert
            AssertRecordEqual(current.Single(), records.Single(t => t.QName == "a").Record);
        }

        [Test]
        public void Succees_WillReturnRecordWithMaxDomainName()
        {
            var domainName = $"{new string('a', 63)}." +
                $"{new string('b', 63)}." +
                $"{new string('c', 63)}." +
                $"{new string('d', 61)}";

            var expected = records.Single(t => t.QName == domainName);
            
            // act
            var current = QueryServer(expected.QName, QType.A);

            // assert
            AssertRecordEqual(current.Single(), expected.Record);
        }

        [Test]
        public void Succeed_TXT_MaxLengthOfCharacterString()
        {
            // arrange
            var expected = records.Single(t => t.QName == "www.max-txt.pl");

            // act
            var current = QueryServer(expected.QName, QType.TXT).Single();

            // assert
            AssertRecordEqual(current, expected.Record);
        }

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
                    
                    break;
                case QType.TXT:
                case QType.MD: 
                case QType.MF: 
                case QType.NS:  break;
                case QType.CNAME:  break;
                
            }

            switch (expected.Type)
            {
                case QType.A:
                    Assert.That(DnsSerialize.Ipv4ToUInt(current.IP4Address) == (expected.RData as RDataA).Address, "A ipv4 not equal");
                    break;
                case QType.NS:
                    Assert.That((expected.RData as RDataNS).NSDName == current.NameHost);
                    break;
                case QType.MD:
                    Assert.That((expected.RData as RDataMD).MADName == current.NameHost);
                    break;
                case QType.MF:
                    Assert.That((expected.RData as RDataMF).MADName == current.NameHost);
                    break;
                case QType.CNAME:
                    Assert.That((expected.RData as RDataCNAME).CName == current.NameHost);
                    break;
                case QType.SOA:
                    RDataSOA soa = (RDataSOA)expected.RData;
                    Assert.That(soa.Expire == current.TimeToExpiration, "SOA.Expire");
                    Assert.That(soa.Minimum == current.DefaultTTL, "SOA.Minimum");
                    Assert.That(soa.MName == current.PrimaryServer, "SOA.MName");
                    Assert.That(soa.Refresh == current.TimeToZoneRefresh, "SOA.Refresh");
                    Assert.That(soa.Retry == current.TimeToZoneFailureRetry, "SOA.Retry");
                    Assert.That(soa.RName == current.NameAdministrator, "SOA.RName");
                    Assert.That(soa.Serial == current.SerialNumber, "SOA.Serial");
                    break;
                case QType.MB:
                    Assert.That(((RDataMB)expected.RData).MADName == current.NameHost, "MB.Namehost");
                    break;
                case QType.MG:
                    Assert.That(((RDataMG)expected.RData).MGMName == current.NameHost, "MGMName");
                    break;
                case QType.MR:
                    Assert.That(((RDataMR)expected.RData).NewName == current.Server, "MR.NewName");
                    break;
                case QType.NULL:
                    throw new NotImplementedException(
                        "problems with powershell - for now not implemented - todo implement. Powershell does not return anything");
                case QType.WKS:
                    // Powershell not work (not sure why for now) with WKS 
                    // this need future investionation, for now this will work like that
                    // nslookup works ok
                    RDataWKS wks = (RDataWKS)expected.RData;
                    Assert.That(wks.Protocol == current.Protocol);
                    Assert.That(wks.Address == DnsSerialize.Ipv4ToUInt(current.IP4Address));
                    break;
                case QType.PTR:
                    Assert.That(((RDataPTR)expected.RData).PtrDName == current.NameHost, "PTR");
                    break;
                case QType.HINFO:
                    RDataHINFO hinfo = (RDataHINFO)expected.RData;
                    Assert.That(current.Text.Contains(hinfo.CPU) && current.Text.Contains(hinfo.OS), "HINFO");
                    break;
                case QType.MINFO:
                    RDataMINFO minfo = (RDataMINFO)expected.RData;
                    Assert.That(minfo.RMailbx == current.NameMailbox && minfo.EMailbx == current.NameErrorsMailbox, "minfo");
                    break;
                case QType.MX:
                    RDataMX mx = (RDataMX)expected.RData;
                    Assert.That(mx.Preference == current.Preference && mx.Exchange == current.Exchange, "MX");
                    break;
                case QType.TXT:
                    Assert.That((expected.RData as RDataTXT).TxtData.All(t =>  current.Text.Contains(t)), "TXT not match");
                    break;
                case QType.AAAA:
                    var currentIpv6 = IPAddress.Parse(current.IP6Address).GetAddressBytes();
                    Assert.That(currentIpv6.SequenceEqual(((RDataAAAA)expected.RData).IPv6), "AAAA");
                        break;
                case QType.MAILB:
                case QType.MAILA:
                case QType.AXFR:
                case QType.All:
                    Assert.IsTrue(false, "must never happen - invalid expected type (invalid test case) - this are only in query section not in result");
                    break;
                default:
                    throw new NotImplementedException("todo implement other QType conditions");
            }
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


        // all tests runs under single server with these records
        // all record current server have
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
            new InMemRRData("www.all-rrs.pl", QClass.IN, QType.NULL, "all-rrs-NULL", 1234, new RDataNULL() { Anything = Encoding.ASCII.GetBytes("NULL Record - anything") }),
            new InMemRRData("www.all-rrs.pl", QClass.IN, QType.WKS, "all-rrs-WKS", 1234, new RDataWKS()
            {
                Address = 0x332211aa,
                // powershell not work well (contrary to nslookup) with WKS
                // not sure why need future investigations. this will work for now (not sure why work)
                // nslookup shows correct values (maybe powershell need some alignment to 8-16 bytes?)
                // nslookup -type=wks - 127.0.0.1
                // (now type into console following:)
                // > www.all-rrs.pl
                Bitmap = new byte[] { 0, 0, 0, (byte)((1 << 6)) },
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
            new InMemRRData("www.all-rrs.pl", QClass.IN, QType.TXT, "all-rrs-TXT", 1234,
                new RDataTXT()
                {
                    TxtData = new string[] { "www.all-rrs-txt-1.pl", "www.all-rrs-txt-2" }
                }),

            new InMemRRData("www.all-rrs.pl", QClass.IN, QType.AAAA, "all-rrs-AAAA", 1234, new RDataAAAA()
            {
                IPv6 = new byte[] {0, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 }
            }),

            // end of all-rrs

            new InMemRRData("www.domain-with-dot.pl.", QClass.IN, QType.A, "domain-with-dot.pl", 111, new RDataA() { Address = 0xaabbaaaa }),
            new InMemRRData("www.domain-with-no-dot-at-the-end.pl", QClass.IN, QType.A, "www.domain-with-no-dot-at-the-end.pl", 111, new RDataA() { Address = 0x11223344 }),

            // min domain name len
            new InMemRRData("a", QClass.IN, QType.A, "a", 4123, new RDataA() { Address = 0x11112222 }),

            // max domain name
            new InMemRRData(
                $"{new string('a', 63)}." +
                $"{new string('b', 63)}." +
                $"{new string('c', 63)}." +
                $"{new string('d', 61)}",
                QClass.IN, QType.A, "max-domain-name-length", 4123, new RDataA() { Address = 0xbb33dd22 }),

            // max txt
            new InMemRRData("www.max-txt.pl", QClass.IN, QType.TXT, "testplname", 111, new RDataTXT() { TxtData = new string[] { new string('a', 255) } }),

            // tcp large amount of data (txt)
            new InMemRRData("www.tcp-large-data.pl", QClass.IN, QType.TXT, "tcp-large-data", 555, new RDataTXT()
            {
                TxtData = new string[] { new string('a', 255), new string('b', 255), new string('c', 255), new string('d', 255), new string('e', 255), }
            }),
            new InMemRRData("www.tcp-large-data.pl", QClass.IN, QType.TXT, "tcp-large-data", 555, new RDataTXT()
            {
                TxtData = new string[] { new string('f', 255), new string('g', 255), new string('h', 255), new string('i', 255), new string('j', 255), }
            }),
            new InMemRRData("www.tcp-large-data.pl", QClass.IN, QType.TXT, "tcp-large-data", 555, new RDataTXT()
            {
                TxtData = new string[] { new string('k', 255), new string('l', 255), new string('m', 255), new string('n', 255), new string('o', 255), }
            }),

            // multiple parallel
            //"www.multiple-parralel"
            new InMemRRData("www.multiple-parralel", QClass.IN, QType.A, "www.multiple-parralel", 174, new RDataA() { Address = 0x0a0b0c0d }),
            new InMemRRData("www.multiple-parralel", QClass.IN, QType.A, "www.multiple-parralel", 111, new RDataA() { Address = 0x0a1b0c0d }),
            new InMemRRData("www.multiple-parralel", QClass.IN, QType.A, "www.multiple-parralel", 7332, new RDataA() { Address = 0x0a2b0c0d }),
            new InMemRRData("www.multiple-parralel", QClass.IN, QType.A, "www.multiple-parralel", 8576, new RDataA() { Address = 0x0a3b0c0d }),

            new InMemRRData("www.exceed-512-bytes.pl", QClass.IN, QType.TXT, "exceed-512-bytes", 9203, 
                new RDataTXT()
                {
                    TxtData = new string[] { new string('a', 200), new string('c', 200), new string('b', 200)
                }}),
            
            new InMemRRData("www.test.pl", QClass.IN, QType.A, "testplname", 111, new RDataA() { Address = 0x44332211 }),


            new InMemRRData("www.test.pl", QClass.HS, QType.A, "testplname", 111, new RDataA() { Address = 0x44332211 }),
            new InMemRRData("www.test.pl", QClass.CS, QType.A, "testplname", 111, new RDataA() { Address = 0x44332211 }),
            new InMemRRData("www.test.pl", QClass.CH, QType.A, "testplname", 111, new RDataA() { Address = 0x44332211 }),

            new InMemRRData("www.google1.pl", QClass.IN, QType.A, "testplname", 111, new RDataA() { Address = 0x44332211 })
        };

        class PwshRecord
        {
            public string IP6Address { get; set; }
            public string IP4Address { get; set; }
            public string Name { get; set; }

            /// <summary>
            /// MB.MADName
            /// </summary>
            public string NameHost { get; set; }
            public int Type { get; set; }
            public int CharacterSet { get; set; }
            public int Section { get; set; }
            public int DataLength { get; set; }
            public int TTL { get; set; }
            public string Address { get; set; }
            public string IPAddress { get; set; }
            public int QueryType { get; set; }
            public string[] Text { get; set; }

            /// <summary>
            /// MX.Preference
            /// </summary>
            public int Preference { get; set; }

            /// <summary>
            /// MX.Exchange
            /// </summary>
            public string Exchange { get; set; }

            /// <summary>
            /// MINFO.RMailbx
            /// </summary>
            public string NameMailbox { get; set; }

            /// <summary>
            /// MINFO.EMailbx
            /// </summary>
            public string NameErrorsMailbox {get; set; }

            /// <summary>
            /// MR.NewName
            /// </summary>
            public string Server { get; set; }

            /// <summary>
            /// SOA.MName
            /// </summary>
            public string PrimaryServer { get; set; }

            /// <summary>
            /// SOA.RName
            /// </summary>
            public string NameAdministrator { get; set; }

            /// <summary>
            /// SOA.SerialNumber
            /// </summary>
            public uint SerialNumber { get; set; }
            
            /// <summary>
            /// SOA.Refresh
            /// </summary>
            public int TimeToZoneRefresh { get; set; }

            /// <summary>
            /// SOA.Retry
            /// </summary>
            public int TimeToZoneFailureRetry { get; set; }

            /// <summary>
            /// SOA.Expire
            /// </summary>
            public int TimeToExpiration { get; set; }

            /// <summary>
            /// SOA.Minimum
            /// </summary>
            public int DefaultTTL { get; set; }

            /// <summary>
            /// WKS.Bitmap
            /// </summary>
            public byte[] Bitmask { get; set; }

            /// <summary>
            /// WKS.Protocol
            /// </summary>
            public byte Protocol { get; set; }
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
