using Arctium.Protocol.DNS;
using Arctium.Protocol.DNS.Resolver;
using System.Net;

namespace Arctium.UnitTests.Protocol
{
    [TestFixture]
    public class DnsResolverTests
    {
        #region RFC-8484

        ///<summary>
        /// Determining whether or not a DoH implementation requires HTTP cookie
        /// [RFC6265] support is particularly important because HTTP cookies are
        /// the primary state tracking mechanism in HTTP.  HTTP cookies SHOULD
        /// NOT be accepted by DOH clients unless they are explicitly required by
        /// a use case.
        /// </summary>
        [Test]
        public void DoH_ClientWillNotAcceptCookiesByDefault()
        {
            //maybe use c# system.HttpListener  for this test to mock server 
            Assert.Fail();
        }

        ///<summary>
        /// DoH clients can request an uncached copy of a HTTP response by using
        /// the "no-cache" request Cache-Control directive (see Section 5.2.1.4
        /// of [RFC7234]) and similar controls.  Note that some caches might not
        /// honor these directives, either due to configuration or interaction
        /// with traditional DNS caches that do not have such a mechanism.
        /// </summary>
        [Test]
        public void Doh_ClientWillSendNoCacheHeader()
        {
            Assert.Fail();
        }

        /// <summary>
        /// DoH clients MUST account for the Age response header field's value
        /// [RFC7234] when calculating the DNS TTL of a response.  For example,
        /// if an RRset is received with a DNS TTL of 600, but the Age header
        /// field indicates that the response has been cached for 250 seconds,
        /// the remaining lifetime of the RRset is 350 seconds.  This requirement
        /// applies to both DoH client HTTP caches and DoH client DNS caches.
        /// </summary>
        [Test]
        public void Doh_ClientWillAccountForTheAgeResponseHeaderWhenCalculatingDnsTtl()
        {
            Assert.Fail();
        }

        [Test]
        public void DoH_ThrowsIfNotUsingValidHttps_Rfc8484()
        {
            string notHttps = "http://dns.google/dns-query?dns={0}";
            var options = DnsResolverOptions.CreateDefault();

            Assert.Throws<ArgumentException>(() => options.SetClientMessageIO_DoH(notHttps, DnsResolverMessageIO_Rfc8484DoH.HttpMethod.Post));
            Assert.Throws<ArgumentException>(() => options.SetClientMessageIO_DoH(null, DnsResolverMessageIO_Rfc8484DoH.HttpMethod.Post));
            Assert.Throws<ArgumentException>(() => options.SetClientMessageIO_DoH(string.Empty, DnsResolverMessageIO_Rfc8484DoH.HttpMethod.Post));
            Assert.Throws<ArgumentException>(() => options.SetClientMessageIO_DoH("invalid_url_!@#$trh]'", DnsResolverMessageIO_Rfc8484DoH.HttpMethod.Post));
        }

        #endregion

        [Test]
        public void WillProcessSingleQuery()
        {
            // arrange

            // act

            // assert
            Assert.IsTrue(false);
        }

        [Test]
        public void InvalidResponseCode()
        {
            // arrange

            // act

            // assert
            Assert.IsTrue(false);
        }

        [Test]
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
