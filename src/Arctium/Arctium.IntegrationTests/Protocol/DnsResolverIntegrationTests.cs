using Arctium.Protocol.DNS;
using Arctium.Protocol.DNS.Model;
using Arctium.Protocol.DNS.Resolver;
using Arctium.Protocol.DNS.Server;
using Newtonsoft.Json;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Arctium.IntegrationTests.Protocol
{
    [TestFixture]
    public class DnsResolverIntegrationTests
    {
        #region RFC-8484

        [Test]
        public void Success_DoH_WillResolveGoogleHostNameOverHttpsPost_Rfc8484()
        {
            var options = DnsResolverOptions.CreateDefault();
            options.SetClientMessageIO_DoH("https://dns.google/dns-query", DnsResolverMessageIO_Rfc8484DoH.HttpMethod.Post);
            var resolver = new DnsResolver(options);

            var result = resolver.ResolveHostNameToHostAddressAsync("www.google.com").Result;

            Assert.That(result.Any());
        }

        [Test]
        public void Success_DoH_WillResolveGoogleHostNameOverHttpsGet_Rfc8484()
        {
            var options = DnsResolverOptions.CreateDefault();
            options.SetClientMessageIO_DoH("https://dns.google/dns-query?dns={0}", DnsResolverMessageIO_Rfc8484DoH.HttpMethod.Get);
            var resolver = new DnsResolver(options);
            
            var result = resolver.ResolveHostNameToHostAddressAsync("www.google.com").Result;

            Assert.That(result.Any());
        }

        #endregion

        #region RFC1035

        /// <summary>
        /// rfc 1035, page 34
        /// </summary>
        [Test]
        public void Success_WillQueryOtherServerIfOneThrowsErrorOrNotWork()
        {
            // arrange
            var sbelt = new ResourceRecord[]
            {
                // one fake - will not work, intentionally 'com' to be selected first by a resolver
                // fake ip 1.2.3.4
                new ResourceRecord() { Class = QClass.IN, Type = QType.NS, Name = "com", TTL = 1000, RData = new RDataNS("dns.notexists.com") },
                new ResourceRecord() { Class = QClass.IN, Type = QType.A, Name = "dns.notexists.com", TTL = 1000, RData = new RDataA("1.2.3.4") },

                // one real - root server that will allow perform real resolve
                new ResourceRecord() { Class = QClass.IN, Type = QType.NS, Name = "", TTL = 1000, RData = new RDataNS("a.root-servers.net") },
                new ResourceRecord() { Class = QClass.IN, Type = QType.A, Name = "a.root-servers.net", TTL = 1000, RData = new RDataA("198.41.0.4") },
            };

            var options = DnsResolverOptions.CreateDefault();
            options.SetSBeltServers(sbelt);

            var resolver = new DnsResolver(options);

            // act
            var result = resolver.ResolveHostNameToHostAddressAsync("www.google.com").Result;

            // assert
            Assert.That(result.Any());
        }

        /// <summary>
        /// rfc page 31, However, when performing the general function, the resolver should not pursue aliases when the CNAME RR matches the query type.
        /// </summary>
        [Test]
        public void Success_GeneralLookupFunction_ReturnsOnlyCNAMEIdAskedForCNAME()
        {
            var resolver = CreateResolver();
            var result = resolver.ResolveGeneralLookupFunctionAsync("www.amazon.com", QClass.IN, QType.CNAME).Result;
            
            Assert.That(result.Any());
            Assert.That(result.Length == 1);
            Assert.That(result[0].Type == QType.CNAME);
        }

        /// <summary>
        /// rfc page 31, In most cases a resolver simply restarts the query at the new name whenit encounters a CNAME
        /// </summary>
        [Test]
        public void Success_ResolveWillAutomaticallyQueryServerAgainWhenServerReturnsCNAME()
        {
            // arrange
            var cache = new InMemoryDnsResolverCache();
            var options = DnsResolverOptions.CreateDefault();
            options.Cache = cache;

            // act
            var resolver = new DnsResolver(options);
            var result = resolver.ResolveHostNameToHostAddressAsync("www.microsoft.com").Result;

            // assert
            // if cache has cname and result has any records means that
            // resolved encountered 'cname' and resolved to ip
            Assert.That(result.Any());
            Assert.That(cache.TryGet("www.microsoft.com", QClass.IN, QType.CNAME, out var _));
        }

        #endregion

        #region NO-RFC

        [Test]
        public void Success_GeneralLookupFunction_SomeRecordTypes()
        {
            // arrange
            DnsResolver resolver = CreateResolver();

            // act
            var r1 = resolver.ResolveGeneralLookupFunctionAsync("gmail.com", QClass.IN, QType.MX).Result;
            var r2 = resolver.ResolveGeneralLookupFunctionAsync("www.gmail.com", QClass.IN, QType.TXT).Result;
            var r3 = resolver.ResolveGeneralLookupFunctionAsync("gmail.com", QClass.IN, QType.AAAA).Result;
            var r4 = resolver.ResolveGeneralLookupFunctionAsync("gmail.com", QClass.IN, QType.NS).Result;

            // assert
            Assert.That(r1.Length > 0 && r1.All(t => t.Type == QType.MX));
            Assert.That(r2.Length > 0 && r2.All(t => t.Type == QType.TXT));
            Assert.That(r3.Length > 0 && r3.All(t => t.Type == QType.AAAA));
            Assert.That(r4.Length > 0 && r4.All(t => t.Type == QType.NS));
        }

        [Test]
        public void Success_StubResolveWillWork()
        {
            var options = DnsResolverOptions.CreateDefault();
            
            // recursion desired then 'stub resolver'
            options.RecursionDesired = true;
            options.SBeltServers = DnsWellKnownServers.DnsGoogle.AsResourceRecords;
            var resolver = new DnsResolver();

            var result1 = resolver.ResolveHostNameToHostAddressAsync("www.google.com").Result;
            var result2 = resolver.ResolveHostNameToHostAddressAsync("www.microsoft.com").Result;
            var result3 = resolver.ResolveHostNameToHostAddressAsync("www.gmail.com").Result;
            var result4 = resolver.ResolveHostNameToHostAddressAsync("www.youtube.com").Result;

            Assert.That(result1.Any());
            Assert.That(result2.Any());
            Assert.That(result3.Any());
            Assert.That(result4.Any());
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

            var options = DnsResolverOptions.CreateDefault();
            options.Cache = fakeCache;
            DnsResolver resolver = new DnsResolver(options);

            var result = resolver.ResolveHostNameToHostAddressAsync(domainName).Result;

            Assert.That(result.Length == 2);
            Assert.That(result.Single(t => t.AddressFamily == AddressFamily.InterNetworkV6).ToString() == ipv6);
            Assert.That(result.Single(t => t.AddressFamily == AddressFamily.InterNetwork).ToString() == ipv4);
        }

        [Test]
        public void Success_WillCacheResponse()
        {
            // arrange
            InMemoryDnsResolverCache fakeCache = new InMemoryDnsResolverCache(true);
            var options = DnsResolverOptions.CreateDefault();
            options.Cache = fakeCache;
            DnsResolver resolver = new DnsResolver(options);

            // act
            var result = resolver.ResolveHostNameToHostAddressAsync("www.google.com").Result;

            // assert
            Assert.That(fakeCache.TryGet("www.google.com", QClass.IN, QType.A, out var cachedRrs) && cachedRrs.Length > 0);
        }

        //
        // No-rfc tests
        //

        [Test]
        public void Success_WillResolveIPv4AndIPv6()
        {
            DnsResolver resolver = CreateResolver();

            IPAddress[] addresses = resolver.ResolveHostNameToHostAddressAsync("www.google.com").Result;

            Assert.That(addresses.Any(t => t.AddressFamily == AddressFamily.InterNetwork));
            Assert.That(addresses.Any(t => t.AddressFamily == AddressFamily.InterNetworkV6));
        }

        [Test]
        public void Success_SimpleWillResolveDomainNameAddress()
        {
            // arrange
            var dnsResolver = CreateResolver();
            // act
            var result = dnsResolver.ResolveHostNameToHostAddressAsync("www.google.com").Result;

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
            var domainName = dnsResolver.ResolvePtrReverseResolution(IPAddress.Parse("8.8.4.4")).Result;

            // assert
            Assert.IsTrue(domainName == "dns.google");
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

        #endregion

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

