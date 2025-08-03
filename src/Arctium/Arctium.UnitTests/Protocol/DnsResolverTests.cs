using Arctium.Protocol.DNS;
using System;
using System.Collections.Generic;
using System.Linq;
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
    }
}
