using Arctium.Protocol.DNS;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.UnitTests.Protocol
{
    [TestFixture]
    public class DnsResolverTests
    {
        [Test]
        public void WillResolveDomainNameToHostAddress()
        {
            // arrange
            var dnsResolver = new DnsResolver();

            // act
            var result = dnsResolver.ResolveHostNameToHostAddress("www.google.com");

            // assert
            Assert.True(false);
        }

        [Test]
        public void WillResolveHostAddressToDomainName()
        {
            // arrange
            var dnsResolver = new DnsResolver();

            // act
            var q = dnsResolver.ResolveHostAddressToHostName(IPAddress.Parse("1.2.3.4"));

            // assert
            Assert.IsTrue(false);
        }

        [Test]
        public void WillResolveGeneralLookupFunction()
        {
            // arrange
            var dnsResolver = new DnsResolver();

            // act
            var a = dnsResolver.ResolveGeneralLookupFunction();

            // assert
            Assert.IsTrue(false);
        }
    }
}
