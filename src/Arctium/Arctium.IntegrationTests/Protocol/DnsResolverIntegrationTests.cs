using Arctium.Protocol.DNS;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.IntegrationTests.Protocol
{
    [TestFixture]
    public class DnsResolverIntegrationTests
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

        private void asdf()
        {
            ProcessStartInfo startInfo = new ProcessStartInfo();
            startInfo.FileName = @"powershell.exe";
            startInfo.Arguments = @"& 'c:\Scripts\test.ps1'";
            startInfo.RedirectStandardOutput = true;
            startInfo.RedirectStandardError = true;
            startInfo.UseShellExecute = false;
            startInfo.CreateNoWindow = true;
            Process process = new Process();
            process.StartInfo = startInfo;
            process.Start();

            string output = process.StandardOutput.ReadToEnd();
            Assert.IsTrue(output.Contains("StringToBeVerifiedInAUnitTest"));

            string errors = process.StandardError.ReadToEnd();
            Assert.IsTrue(string.IsNullOrEmpty(errors));
        }
    }
}
