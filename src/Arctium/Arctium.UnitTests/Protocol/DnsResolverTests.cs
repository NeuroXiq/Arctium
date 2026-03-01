using Arctium.Protocol.DNS;
using System.Net;

namespace Arctium.UnitTests.Protocol
{
    [TestFixture]
    public class DnsResolverTests
    {
        public void WillProcessSingleQuery()
        {
            // arrange

            // act

            // assert
            Assert.IsTrue(false);
        }

        public void InvalidResponseCode()
        {
            // arrange

            // act

            // assert
            Assert.IsTrue(false);
        }

        public void WillConsiderMaxResponseTTLSeconds()
        {
            // arrange

            // act

            // assert
            Assert.IsTrue(false);
        }

        [Test]
        public void WillResolveDomainNameToHostAddress()
        {
            // arrange
            var dnsResolver = new DnsResolver();

            // act
            var result = dnsResolver.ResolveHostNameToHostAddressAsync("www.google.com").Result;

            // assert
            Assert.True(false);
        }

        [Test]
        public void WillResolveGeneralLookupFunction()
        {
            // arrange
            var dnsResolver = new DnsResolver();

            // act
            Object a = null; // dnsResolver.ResolveGeneralLookupFunction();

            // assert
            Assert.IsTrue(false);
        }

        /// <summary>
        ///  RFC-1034 5.2.2. Aliases
        /// </summary>
        [Test]
        public void WillResolveAliasName()
        {
            // arrange

            // act

            // assert
            Assert.IsTrue(false);
        }

        [Test]
        public void WillUseCache()
        {
            // arrange

            // act

            // assert
            Assert.IsTrue(false);
        }

        [Test]
        public void WillAskFirstDnsServersFromOptions()
        {
            // arrange

            // act

            // assert
            Assert.IsTrue(false);
        }
        
    }
}
