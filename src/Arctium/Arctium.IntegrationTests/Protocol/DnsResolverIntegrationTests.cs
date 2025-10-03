using Arctium.Protocol.DNS;
using System.Net;

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
            
        }

        [Test]
        public void Success_WillPutInCacheResponse()
        {
            // arrange

            // act

            // assert
            Assert.IsTrue(false);
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

        [Test]
        public void Success_SimpleWillResolveDomainNameAddress()
        {
            // arrange
            var dnsResolver = new DnsResolver();
            
          



            // act
            var result = dnsResolver.ResolveHostNameToHostAddress("www.google.com");

            // assert
            Assert.True(false);
        }

        [Test]
        public void Success_WillResolveAddressToDomainName()
        {
            // arrange
            var dnsResolver = new DnsResolver();

            // act
            var q = dnsResolver.ResolveHostAddressToHostName(IPAddress.Parse("1.2.3.4"));

            // assert
            Assert.IsTrue(false);
        }
    }
}

