using Arctium.Protocol.DNS;
using Arctium.Protocol.DNS.Model;
using Newtonsoft.Json;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

namespace Arctium.IntegrationTests.Protocol
{
    [TestFixture]
    public class DnsResolverIntegrationTests
    {
        /// <summary>
        /// rfc 1035, page 34
        /// </summary>
        [Test]
        public void Success_WillQueryOtherServerIfOneThrowsErrorOrNotWork()
        {
            // arrange

            // act

            // assert
            Assert.IsTrue(false);
        }

        /// <summary>
        /// rfc page 31, However, when performing the general function, the resolver should not pursue aliases when the CNAME RR matches the query type.
        /// </summary>
        [Test]
        public void Success_NotStandardCase_ResolverWillReturnCNAMERecordWithoutQueryServerAgainIfUserWants()
        {

        }

        /// <summary>
        /// rfc page 31, In most cases a resolver simply restarts the query at the new name whenit encounters a CNAME
        /// </summary>
        [Test]
        public void Success_StandardCase_ResolveWillAutomaticallyQueryServerAgainWhenServerReturnsCNAME()
        {
            // arrange

            // act

            // assert
            Assert.IsTrue(false);
        }

        /// <summary>
        /// 
        /// </summary>
        [Test]
        public void Success_WillReturnResponseFromCache()
        {
            string domainName = "www.cached-name.com";
            string ipv4 = "1.2.3.4";
            string ipv6 = "1:2:3:4:5:6:7:8";
            
            InMemoryDnsResolverCache fakeCache = new InMemoryDnsResolverCache(true);

            fakeCache.Set(new ResourceRecord[]
            {
                new ResourceRecord()
                {
                    Class = QClass.IN,
                    TTL = 12345,
                    Name = domainName,
                    Type = QType.A,
                    RData = new RDataA(ipv4)
                },
                new ResourceRecord()
                {
                    Class = QClass.IN,
                    TTL = 12345,
                    Name = domainName,
                    Type = QType.AAAA,
                    RData = new RDataAAAA(IPAddress.Parse(ipv6).GetAddressBytes())
                }
            });

            DnsResolver resolver = new DnsResolver(DnsResolverOptions.CreateDefault(fakeCache));

            var result = resolver.ResolveHostNameToHostAddress(domainName);

            Assert.That(result.Length == 2);
            Assert.That(result.Single(t => t.AddressFamily == AddressFamily.InterNetworkV6).ToString() == ipv6);
            Assert.That(result.Single(t => t.AddressFamily == AddressFamily.InterNetwork).ToString() == ipv4);
        }

        [Test]
        public void Success_WillCacheResponse()
        {
            // arrange
            InMemoryDnsResolverCache fakeCache = new InMemoryDnsResolverCache(true);
            DnsResolver resolver = new DnsResolver(DnsResolverOptions.CreateDefault(fakeCache));

            // act
            var result = resolver.ResolveHostNameToHostAddress("www.google.com");

            // assert
            Assert.That(fakeCache.TryGet("www.google.com", QClass.IN, QType.A, out var cachedRrs) && cachedRrs.Length > 0);
        }

        [Test]
        public void Success_WillQueryOnlySpecificServer()
        {
            // arrange

            // act

            // assert
            Assert.IsTrue(false);
        }

        /// <summary>
        /// rfc 1035, QTYPE
        /// </summary>
        [Test]
        public void Success_WillWorkWithAllQTypes()
        {

        }

        //
        // No-rfc tests
        //

        [Test]
        public void Success_WillResolveIPv4AndIPv6()
        {
            DnsResolver resolver = CreateResolver();

            IPAddress[] addresses = resolver.ResolveHostNameToHostAddress("www.google.com");

            Assert.That(addresses.Any(t => t.AddressFamily == AddressFamily.InterNetwork));
            Assert.That(addresses.Any(t => t.AddressFamily == AddressFamily.InterNetworkV6));
        }

        [Test]
        public void Success_SimpleWillResolveDomainNameAddress()
        {
            // arrange
            var dnsResolver = CreateResolver();
            // act
            var result = dnsResolver.ResolveHostNameToHostAddress("www.google.com");

            // assert
            Assert.That(result.Any(t => t.AddressFamily == AddressFamily.InterNetwork));
            Assert.That(result.Any(t => t.AddressFamily == AddressFamily.InterNetworkV6));
        }

        [Test]
        public void Success_WillResolveAddressToDomainName()
        {
            // arrange
            var dnsResolver = CreateResolver();

            // act
            var result = dnsResolver.ResolveHostAddressToHostName(IPAddress.Parse("1.2.3.4"));

            // assert
            Assert.IsTrue(false);
        }

        [Test]
        public void Success_WillWorkWithUdp()
        {
            var m = new Message();

            m.Question = new Question[]
            {
                new Question()
                {
                    QClass = QClass.IN,
                    QName = "www.google.com",
                    QType = QType.A
                }
            };

            m.Header = new Header
            {
                Id = 1234,
                QDCount = 1,
                RCode = ResponseCode.NoErrorCondition,
                RD = true,
                QR = QRType.Query,
            };

            var result = DnsResolver.SendDnsUdpMessageAsync(m, IPAddress.Parse("8.8.8.8"), 53).Result;

            Assert.That(result?.Answer.Length > 0);
            Assert.That(result?.Answer.FirstOrDefault(t => t.Type == QType.A) != null);
        }

        [Test]
        public void Success_WillWorkWithTcp()
        {
            var m = new Message();

            m.Question = new Question[]
            {
                new Question()
                {
                    QClass = QClass.IN,
                    QName = "www.google.com",
                    QType = QType.A
                }
            };

            m.Header = new Header
            {
                Id = 1234,
                QDCount = 1,
                RCode = ResponseCode.NoErrorCondition,
                RD = true,
                QR = QRType.Query,
            };

            var result = DnsResolver.SendDnsTcpMessageAsync(m, IPAddress.Parse("8.8.8.8"), 53).Result;

            Assert.That(result?.Answer.Length > 0);
            Assert.That(result?.Answer.FirstOrDefault(t => t.Type == QType.A) != null);
        }

        [Test]
        public void Success_WillWorkWithAllArctiumServerTypes()
        {
            // arrange
            var msg = new Message();
            var server = StartArctiumDnsServer(out var cancellationToken);
            var allQType = Enum.GetValues<QType>();
            var ignoreQType = new QType[] { QType.AXFR, QType.All, QType.MAILA, QType.MAILB };

            foreach (var qtype in allQType)
            {
                msg.Header = new Header()
                {
                    AA = false,
                    ANCount = 0,
                    ARCount = 0,
                    NSCount = 0,
                    QDCount = 1,
                    RA = false,
                    RD = false,
                    Id = 1234,
                    Opcode = Opcode.Query,
                    QR = QRType.Query,
                    RCode = ResponseCode.NoErrorCondition,
                    TC = false,
                };

                msg.Question = new Question[]
                {
                    new Question()
                    {
                        QName = "www.all-rrs.pl",
                        QType = qtype,
                        QClass = QClass.IN
                    }
                };

                // act
                var result = DnsResolver.SendDnsUdpMessageAsync(msg, IPAddress.Loopback, 53).Result;

                // assert
                AssertArctiumServerAnswer(msg, result);
            }

            cancellationToken.Cancel();
        }

        // tools and arctium dns server for tests

        private DnsResolver CreateResolver()
        {
            return new DnsResolver();
        }

        public DnsServer StartArctiumDnsServer(out CancellationTokenSource cts)
        {
            cts = new CancellationTokenSource();
            var cancellationToken = cts.Token;
            var itMasterFiles = CreateArctiumDnsMasterFiles();

            DnsServerOptions options = DnsServerOptions.CreateDefault(itMasterFiles, cancellationToken);
            var server = new DnsServer(options);

            var taskUdp = Task.Run(() => { server.StartUdp(); }, cancellationToken);
            var taskTcp = Task.Run(() => { server.StartTcp(); }, cancellationToken);

            for (int i = 0; i < 5 && (taskUdp.Status != TaskStatus.Running || taskTcp.Status != TaskStatus.Running); i++)
            {
                Task.Delay(500).Wait();
            }

            if (taskUdp.Status != TaskStatus.Running || taskTcp.Status != TaskStatus.Running) throw new Exception("failed to run server task");

            return server;
        }

        void AssertArctiumServerAnswer(Message clientRequest, Message serverResponse)
        {
            var expected = itMasterFiles.Nodes.Where(t => t.Name == clientRequest.Question[0].QName)
                .SelectMany(t => t.Records)
                .Where(t => t.Type == clientRequest.Question[0].QType && clientRequest.Question[0].QClass == t.Class)
                .ToArray();

            var current = serverResponse.Answer;

            Assert.That(expected.Length == current.Length);

            foreach (var e in expected)
            {
                Assert.That(current.Any(c => AreResourceRecordsEqual(c, e)), "missing record");
            }
        }

        bool AreResourceRecordsEqual(ResourceRecord current, ResourceRecord expected)
        {
            var r1 = JsonConvert.SerializeObject(current.RData);
            var r2 = JsonConvert.SerializeObject(expected.RData);

            bool result = current.Name == expected.Name &&
                current.TTL == expected.TTL &&
                current.Type == expected.Type &&
                current.Class == expected.Class &&
                r1 == r2;

            if (!result) Debugger.Break();

            return result;
        }

        static InMemoryDnsServerMasterFiles itMasterFiles;

        static InMemoryDnsServerMasterFiles CreateArctiumDnsMasterFiles()
        {
            itMasterFiles = new InMemoryDnsServerMasterFiles();
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
                Bitmap = new byte[] { 0, 0, 0, (byte)((1 << 6)) },
                Protocol = 6
            });
            t.AddIN("www.all-rrs.pl", QType.PTR, 1234, new RDataPTR() { PtrDName = "www.all-rrs-ptr.pl" });
            t.AddIN("www.all-rrs.pl", QType.HINFO, 1234, new RDataHINFO() { CPU = "www.all-rrs-cpu.pl", OS = "www.all-rrs-cpu.pl" });
            t.AddIN("www.all-rrs.pl", QType.MINFO, 1234, new RDataMINFO() { EMailbx = "www.all-rrs-minfo-emailbx", RMailbx = "www.all-rrs-minfo-rmailbx" });
            t.AddIN("www.all-rrs.pl", QType.MX, 1234, new RDataMX() { Preference = 5555, Exchange = "www.all-rrs-exchange" });
            t.AddIN("www.all-rrs.pl", QType.TXT, 1234, new RDataTXT() { TxtData = new string[] { "www.all-rrs-txt-1.pl", "w", "" } });
            t.AddIN("www.all-rrs.pl", QType.TXT, 1234, new RDataTXT() { TxtData = new string[] { "", "a", "www.all-rrs-txt-1.pl" } });
            t.AddIN("www.all-rrs.pl", QType.AAAA, 1234, new RDataAAAA() { IPv6 = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 } });

            return itMasterFiles;
        }
    }
}

