using Arctium.Protocol.DNS;
using Arctium.Protocol.DNSImpl.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.UnitTests.Protocol
{
    internal class DnsServerTests
    {

        public void MyTestMethod()
        {
            // arrange
            DnsServer server = StartDnsServer();

            // act

            // assert
            Assert.IsTrue(false);
        }

        DnsServer StartDnsServer()
        {
            InMemoryDnsServerDataSource inMemDs = new InMemoryDnsServerDataSource();
            DnsServerOptions options = new DnsServerOptions(inMemDs);
            DnsServer server = new DnsServer(options);

            server.Start(new CancellationToken());

            return server;
        }

        static readonly List<InMemRRData> records = new List<InMemRRData>()
        {
            new InMemRRData("www.test.pl", QClass.IN, QType.A, "testplname", 111, new RDataA() { Address = 0x44332211 })
        };
    }
}
