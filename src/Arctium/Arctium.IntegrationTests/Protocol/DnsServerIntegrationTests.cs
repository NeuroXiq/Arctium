using Arctium.Protocol.DNS;
using Arctium.Protocol.DNS.Model;
using Arctium.Protocol.DNS.Protocol;
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

            DnsServerOptions options = DnsServerOptions.CreateDefault(itMasterFiles, cancellationToken);
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

        // start of 
        // 6.2. Example standard queries [rfc 1034, page 40]

        /// <summary>
        /// 6.2.1. QNAME=SRI-NIC.ARPA, QTYPE=A
        /// </summary>
        [Test]
        public void Succeed_6_2_ExampleStandardQueries1()
        {
            // 6.2.1. QNAME=SRI-NIC.ARPA, QTYPE=A
            var expected = records.Where(t => t.Name == "SRI-NIC.ARPA" && t.Type == QType.A).ToArray();
            var current = QueryServer("SRI-NIC.ARPA.", QType.A);

            AssertSetsEquals(current, expected);
        }

        // end of 
        // 6.2. Example standard queries [rfc 1034, page 40]

        //
        // rfc
        //

        /// <summary>
        ///  
        /// </summary>


        /// <summary>
        /// rfc1035, p. 25, 4.3.3. Wildcards
        /// </summary>
        [Test]
        public void Success_WildcardDomainsWorks()
        {

        }

        /// <summary>
        /// rfc1035 page 26
        /// </summary>
        [Test]
        public void Succeed_WillWorkWithWildcards()
        {
            // arrange

            // act

            // assert
            Assert.IsTrue(false);
        }


        [Test]
        public void Success_Flag_RecursionAvailableWorks()
        {
            // arrange

            // act

            // assert
            Assert.IsTrue(false);
        }

        [Test]
        public void Success_Flag_AuthoritativeAnswerWorks()
        {
            Assert.IsTrue(false);
        }

        /// <summary>
        /// rfc1035, page 17 | while the additional section might be
        /// </summary>
        [Test]
        public void Success_AdditionalRecords_WillReturnAdditionalARecordsIfAskedForMX()
        {
            Assert.IsTrue(false);
        }

        [Test]
        public void Success_AXFR_ZoneTranser()
        {
            // arrange

            // act

            // assert
            Assert.IsTrue(false);
        }

        /// <summary>
        /// rfc1035 page 18,  3.7.2. Inverse queries (Optional)
        /// </summary>
        [Test]
        public void Success_WillWorkWithInverseQuery()
        {
            // arrange

            // act

            // assert
            Assert.IsTrue(false);
        }

        /// <summary>
        /// ???
        /// </summary>
        [Test]
        public void Success_RecursionDesired_WillRecurseToOtherServer()
        {
            Assert.True(false);
        }

        /// <summary>
        /// rfc1035, page 15 | PTR
        /// </summary>
        [Test]
        public void Succes_PTR_WillPointToPrimaryNameToAlias()
        {
            Assert.True(false);
        }

        /// <summary>
        /// rfc1035, page 15 | CNAME RRs cause special action in DNS software [...]
        /// </summary>
        [Test]
        public void Succeed_CNAME_ServerWillCheckForCName()
        {
            Assert.True(false);
        }

        //
        // non rfc tests
        //

        public void ReturnsError_WillReturnErrorIfSendInvalidDomainName()
        {
            // e.g. domain name:"dsjklg!!#%#%,./+_)" is invalid
        }

        [Test]
        public void Succees_WillWorkTcpWithLargeAmountOfTxtData()
        {
            // arrange
            var expectedRows = records.Where(t => t.Name == "www.tcp-large-data.pl").ToList();

            // act
            var result = QueryServer("www.tcp-large-data.pl", QType.TXT);

            // assert
            Assert.That(expectedRows.Count == result.Count);
            expectedRows.ForEach(e =>
            {
                var expected = e;
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
        public void Success_ReturnsAdditionalRecords()
        {
            // arrange

            // act

            // assert
            Assert.IsTrue(false);
        }

        [Test]
        public void Success_ReturnsAuthorityRecords()
        {
            // arrange

            // act

            // assert
            Assert.IsTrue(false);
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
                var expected = records.First(r => r.Name == "www.all-rrs.pl" && r.Type == qtype);
                Assert.That(result.Count == 1);
                
                // assert
                AssertRecordEqual(result[0], expected);
            }
        }

        [Test]
        public void Succeed_WhenExceed512BytesWillReturnTrunCated()
        {
            // arrange
            var expected = records.Single(t => t.Name == "www.exceed-512-bytes.pl");

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
            var expected = records.Single(t => t.Name == "www.domain-with-dot.pl.");

            // assert
            AssertRecordEqual(current, expected);
        }

        [Test]
        public void Succeed_ReturnRDataA_DomainNameWithoutDotAtTheEnd()
        {
            // act
            var current = QueryServer("www.domain-with-no-dot-at-the-end.pl", QType.A);

            // assert
            AssertRecordEqual(current.Single(), records.Single(t => t.Name == "www.domain-with-no-dot-at-the-end.pl"));
        }

        [Test]
        public void WillReturnRecordWithMinDomainName()
        {
            // act
            var current = QueryServer("a.", QType.A);

            // assert
            AssertRecordEqual(current.Single(), records.Single(t => t.Name == "a"));
        }

        [Test]
        public void Succees_WillReturnRecordWithMaxDomainName()
        {
            var domainName = $"{new string('a', 63)}." +
                $"{new string('b', 63)}." +
                $"{new string('c', 63)}." +
                $"{new string('d', 61)}";

            var expected = records.Single(t => t.Name == domainName);
            
            // act
            var current = QueryServer(expected.Name, QType.A);

            // assert
            AssertRecordEqual(current.Single(), expected);
        }

        [Test]
        public void Succeed_TXT_MaxLengthOfCharacterString()
        {
            // arrange
            var expected = records.Single(t => t.Name == "www.max-txt.pl");

            // act
            var current = QueryServer(expected.Name, QType.TXT).Single();

            // assert
            AssertRecordEqual(current, expected);
        }

        private static void AssertSetsEquals(IEnumerable<PwshRecord> current, IEnumerable<ResourceRecord> expected)
        {
            Assert.That(current.Count() == expected.Count());

            foreach (var c in current)
            {
                if (!expected.Any(e => AreRecordEqual(c, e, out var _)))
                {
                    Assert.That(false, "failed");
                }
            }

            Assert.That(current.All(c => expected.Any(e => AreRecordEqual(c, e, out _))));
        }

        void AssertRecordEqual(PwshRecord current, ResourceRecord expected)
        {
            bool equal = AreRecordEqual(current, expected, out string errorMessage);
            Assert.That(equal, errorMessage);
        }

        private static bool AreRecordEqual(PwshRecord current, ResourceRecord expected, out string errorMessage)
        {
            string e = null;

            if (current.TTL != expected.TTL ||
                expected.Name != current.Name ||
                (int)expected.Type != current.Type)
            {
                e = "expected != current";
            }

            switch (expected.Type)
            {
                case QType.A:
                    if (DnsSerialize.Ipv4ToUInt(current.IP4Address) != (expected.RData as RDataA).Address) e = "A ipv4 not equal";
                    break;
                case QType.NS:
                    if ((expected.RData as RDataNS).NSDName != current.NameHost) e = "NSDName != NameHost";
                    break;
                case QType.MD:
                    if ((expected.RData as RDataMD).MADName != current.NameHost) e = "MADName";
                    break;
                case QType.MF:
                    if ((expected.RData as RDataMF).MADName != current.NameHost) e = "MADName";
                    break;
                case QType.CNAME:
                    if ((expected.RData as RDataCNAME).CName != current.NameHost) e = "CName";
                    break;
                case QType.SOA:
                    RDataSOA soa = (RDataSOA)expected.RData;
                    if (soa.Expire != current.TimeToExpiration) e = "SOA.Expire";
                    else if(soa.Minimum != current.DefaultTTL) e = "SOA.Minimum";
                    else if(soa.MName != current.PrimaryServer) e = "SOA.MName";
                    else if(soa.Refresh != current.TimeToZoneRefresh) e = "SOA.Refresh";
                    else if(soa.Retry != current.TimeToZoneFailureRetry) e = "SOA.Retry";
                    else if(soa.RName != current.NameAdministrator) e = "SOA.RName";
                    else if(soa.Serial != current.SerialNumber) e = "SOA.Serial";
                    break;
                case QType.MB:
                    if(((RDataMB)expected.RData).MADName != current.NameHost) e = "MB.Namehost";
                    break;
                case QType.MG:
                    if(((RDataMG)expected.RData).MGMName != current.NameHost) e = "MGMName";
                    break;
                case QType.MR:
                    if (((RDataMR)expected.RData).NewName != current.Server) e = "MR.NewName";
                    break;
                case QType.NULL:
                    throw new NotImplementedException(
                        "problems with powershell - for now not implemented - todo implement. Powershell does not return anything");
                case QType.WKS:
                    // Powershell not work (not sure why for now) with WKS 
                    // this need future investionation, for now this will work like that
                    // nslookup works ok
                    RDataWKS wks = (RDataWKS)expected.RData;
                    if (wks.Protocol != current.Protocol) e = "protocol";
                    if (wks.Address != DnsSerialize.Ipv4ToUInt(current.IP4Address)) e = "wks";
                    break;
                case QType.PTR:
                    if(((RDataPTR)expected.RData).PtrDName != current.NameHost) e = "PTR"; ;
                    break;
                case QType.HINFO:
                    RDataHINFO hinfo = (RDataHINFO)expected.RData;
                    if(!current.Text.Contains(hinfo.CPU) || !current.Text.Contains(hinfo.OS)) e = "HINFO";
                    break;
                case QType.MINFO:
                    RDataMINFO minfo = (RDataMINFO)expected.RData;
                    if(minfo.RMailbx != current.NameMailbox || minfo.EMailbx != current.NameErrorsMailbox) e = "minfo";
                    break;
                case QType.MX:
                    RDataMX mx = (RDataMX)expected.RData;
                    if(mx.Preference != current.Preference || mx.Exchange != current.Exchange) e = "MX";
                    break;
                case QType.TXT:
                    if((expected.RData as RDataTXT).TxtData.Any(t => !current.Text.Contains(t))) e = "TXT not match";
                    break;
                case QType.AAAA:
                    var currentIpv6 = IPAddress.Parse(current.IP6Address).GetAddressBytes();
                    if(!currentIpv6.SequenceEqual(((RDataAAAA)expected.RData).IPv6)) e = "AAAA";
                        break;
                case QType.MAILB:
                case QType.MAILA:
                case QType.AXFR:
                case QType.All:
                    e = "must never happen - invalid expected type (invalid test case) - this are only in query section not in result";
                    break;
                default:
                    e = "todo implement other QType conditions";
                    break;
            }

            errorMessage = e;
            return e == null;
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

        static InMemoryDnsServerMasterFiles itMasterFiles;
        static List<ResourceRecord> records;

        static DnsServerIntegrationTests()
        {
            itMasterFiles = new InMemoryDnsServerMasterFiles();
            var r = itMasterFiles;
            // rfc

            r.AddIN(string.Empty, QType.SOA, 300, new RDataSOA()
            {
                MName = "SRI-NIC.ARPA.",
                RName = "HOSTMASTER.SRI-NIC.ARPA.",
                Expire = 604800,
                Minimum = 86400,
                Refresh = 1800,
                Retry = 300,
                Serial = 870611
            });

            r.AddIN("A.ISI.EDU", QType.NS, 300, new RDataNS() { NSDName = "A.ISI.EDU" });
            r.AddIN("A.ISI.EDU", QType.NS, 300, new RDataNS() { NSDName = "C.ISI.EDU" });
            r.AddIN("A.ISI.EDU", QType.NS, 300, new RDataNS() { NSDName = "SRI-NIC.ARPA" });
            r.AddIN("MIL", QType.NS, 86400, new RDataNS() { NSDName = "SRI-NIC.ARPA" });
            r.AddIN("MIL", QType.NS, 86400, new RDataNS() { NSDName = "A.ISI.EDU" });
            r.AddIN("EDU", QType.NS, 86400, new RDataNS() { NSDName = "SRI-NIC.ARPA." });
            r.AddIN("EDU", QType.NS, 86400, new RDataNS() { NSDName = "C.ISI.EDU" });
            r.AddIN("SRI-NIC.ARPA", QType.A, 300, new RDataA("26.0.0.73"));
            r.AddIN("SRI-NIC.ARPA", QType.A, 300, new RDataA("10.0.0.51"));
            r.AddIN("SRI-NIC.ARPA", QType.MX, 300, new RDataA("10.0.0.51"));
            r.AddIN("SRI-NIC.ARPA", QType.HINFO, 300, new RDataHINFO() { CPU = "DEC-2060", OS = "TOPS20" });
            r.AddIN("ACC.ARPA", QType.A, 300, new RDataA("26.6.0.65"));
            r.AddIN("ACC.ARPA", QType.HINFO, 300, new RDataHINFO() { CPU = "PDP-11/70", OS = "UNIX" });
            r.AddIN("ACC.ARPA", QType.MX, 300, new RDataMX() { Preference = 10, Exchange = "ACC.ARPA." });
            r.AddIN("USC-ISIC.ARPA.", QType.CNAME, 300, new RDataCNAME() { CName = "C.ISI.EDU" });
            r.AddIN("73.0.0.26.IN-ADDR.ARPA", QType.PTR, 300, new RDataPTR() { PtrDName = "SRI-NIC.ARPA." });
            r.AddIN("65.0.6.26.IN-ADDR.ARPA", QType.PTR, 300, new RDataPTR() { PtrDName = "ACC.ARPA." });
            r.AddIN("51.0.0.10.IN-ADDR.ARPA", QType.PTR, 300, new RDataPTR() { PtrDName = "SRI-NIC.ARPA." });
            r.AddIN("52.0.0.10.IN-ADDR.ARPA", QType.PTR, 300, new RDataPTR() { PtrDName = "C.ISI.EDU." });
            r.AddIN("103.0.3.26.IN-ADDR.ARPA", QType.PTR, 300, new RDataPTR() { PtrDName = "A.ISI.EDU." });
            r.AddIN("A.ISI.EDU", QType.A, 300, new RDataA("26.3.0.103"));
            r.AddIN("C.ISI.EDU", QType.A, 300, new RDataA("10.0.0.52"));

            // it tests

            // todo: .AddIN(".pl"), (to have valid dns nodes tree)


            var t = itMasterFiles;

            t.AddIN("www.all-rrs.pl", QType.A, 111, new RDataA() { Address = 0x44332211 });
            t.AddIN("www.all-rrs.pl", QType.NS, 1234, new RDataNS() { NSDName = "all-rrs-nsdname.pl" });
            t.AddIN("www.all-rrs.pl", QType.MD, 1234, new RDataMD() { MADName = "www.all-rrs-mdname.pl" });
            t.AddIN("www.all-rrs.pl", QType.MF, 1234, new RDataMF() { MADName = "www.all-rrs-mfname.pl" });
            t.AddIN("www.all-rrs.pl", QType.CNAME, 1234, new RDataCNAME() { CName = "www.all-rrs-cname.pl" });
            t.AddIN("www.all-rrs.pl", QType.SOA, 1234, new RDataSOA()
            {
                Expire = 0x0000005,
                Minimum = 0x00000004,
                MName = "www.all-rrs-soa-mname.pl",
                Refresh = 0x00000006,
                Retry = 0x00000007,
                RName = "www.all-rrs-soa-rname.pl",
                Serial = 0x00000008
            });
            t.AddIN("www.all-rrs.pl", QType.MB, 1234, new RDataMB() { MADName = "www.all-rrs-mb.pl" });
            t.AddIN("www.all-rrs.pl", QType.MG, 1234, new RDataMG() { MGMName = "www.all-rrs-mg.pl" });
            t.AddIN("www.all-rrs.pl", QType.MR, 433, new RDataMR() { NewName = "www.all-rrs-mr.pl" });
            t.AddIN("www.all-rrs.pl", QType.NULL, 1234, new RDataNULL() { Anything = Encoding.ASCII.GetBytes("NULL Record - anything") });
            t.AddIN("www.all-rrs.pl", QType.WKS, 1234, new RDataWKS()
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
            });
            t.AddIN("www.all-rrs.pl", QType.PTR, 1234, new RDataPTR() { PtrDName = "www.all-rrs-ptr.pl" });
            t.AddIN("www.all-rrs.pl", QType.HINFO, 1234, new RDataHINFO() { CPU = "www.all-rrs-cpu.pl", OS = "www.all-rrs-cpu.pl" });
            t.AddIN("www.all-rrs.pl", QType.MINFO, 1234, new RDataMINFO() { EMailbx = "www.all-rrs-minfo-emailbx", RMailbx = "www.all-rrs-minfo-rmailbx" });
            t.AddIN("www.all-rrs.pl", QType.MX, 1234, new RDataMX() { Preference = 5555, Exchange = "www.all-rrs-exchange" });
            t.AddIN("www.all-rrs.pl", QType.TXT, 1234, new RDataTXT() { TxtData = new string[] { "www.all-rrs-txt-1.pl", "www.all-rrs-txt-2" } });
            t.AddIN("www.all-rrs.pl", QType.AAAA, 1234, new RDataAAAA() { IPv6 = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 } });

            // end of all-rrs

            t.AddIN("www.domain-with-dot.pl.", QType.A, 111, new RDataA() { Address = 0xaabbaaaa });
            t.AddIN("www.domain-with-no-dot-at-the-end.pl", QType.A, 111, new RDataA() { Address = 0x11223344 });

            // min domain name len
            t.AddIN("a", QType.A, 4123, new RDataA() { Address = 0x11112222 });

            // max domain name
            t.AddIN(
                $"{new string('a', 63)}." +
                $"{new string('b', 63)}." +
                $"{new string('c', 63)}." +
                $"{new string('d', 61)}",
                QType.A, 4123, new RDataA() { Address = 0xbb33dd22 });

            // max txt
            t.AddIN("www.max-txt.pl", QType.TXT, 111, new RDataTXT() { TxtData = new string[] { new string('a', 255) } });

            // tcp large amount of data (txt)
            t.AddIN("www.tcp-large-data.pl", QType.TXT, 555, new RDataTXT()
            {
                TxtData = new string[] { new string('a', 255), new string('b', 255), new string('c', 255), new string('d', 255), new string('e', 255) }
            });
            t.AddIN("www.tcp-large-data.pl", QType.TXT, 555, new RDataTXT()
            {
                TxtData = new string[] { new string('f', 255), new string('g', 255), new string('h', 255), new string('i', 255), new string('j', 255) }
            });
            t.AddIN("www.tcp-large-data.pl", QType.TXT, 555, new RDataTXT()
            {
                TxtData = new string[] { new string('k', 255), new string('l', 255), new string('m', 255), new string('n', 255), new string('o', 255) }
            });

            // multiple parallel
            //"www.multiple-parralel"
            t.AddIN("www.multiple-parralel", QType.A, 174, new RDataA() { Address = 0x0a0b0c0d });
            t.AddIN("www.multiple-parralel", QType.A, 111, new RDataA() { Address = 0x0a1b0c0d });
            t.AddIN("www.multiple-parralel", QType.A, 7332, new RDataA() { Address = 0x0a2b0c0d });
            t.AddIN("www.multiple-parralel", QType.A, 8576, new RDataA() { Address = 0x0a3b0c0d });

            t.AddIN("www.exceed-512-bytes.pl", QType.TXT, 9203,
                new RDataTXT()
                {
                    TxtData = new string[] { new string('a', 200), new string('c', 200), new string('b', 200)
                }
                });
            
            t.AddIN("www.test.pl", QType.A, 111, new RDataA() { Address = 0x44332211 });


            t.Add("www.test.pl", QClass.HS, QType.A, 111, new RDataA() { Address = 0x44332211 });
            t.Add("www.test.pl", QClass.CS, QType.A, 111, new RDataA() { Address = 0x44332211 });
            t.Add("www.test.pl", QClass.CH, QType.A, 111, new RDataA() { Address = 0x44332211 });

            t.AddIN("www.google1.pl", QType.A, 111, new RDataA() { Address = 0x44332211 });

            records = itMasterFiles.Nodes.SelectMany(t => t.Records).ToList();
        }

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
