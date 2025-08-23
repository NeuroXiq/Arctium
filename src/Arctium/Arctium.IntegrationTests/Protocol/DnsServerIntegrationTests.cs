using Arctium.Protocol.DNS;
using Arctium.Protocol.DNSImpl.Model;
using Newtonsoft.Json;
using System.Diagnostics;

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

            InMemoryDnsServerDataSource inMemDs = new InMemoryDnsServerDataSource();
            DnsServerOptions options = new DnsServerOptions(inMemDs);
            server = new DnsServer(options);

            var task = Task.Run(() => { server.Start(cancellationToken); }, cancellationToken);

            for (int i = 0; i < 5 && task.Status != TaskStatus.Running; i++)
            {
                Task.Delay(500).Wait();
            }

            if (task.Status != TaskStatus.Running) throw new Exception("failed to run server task");
        }

        [OneTimeTearDown]
        public void OntTimeTearDown()
        {
            serverStop.Cancel();
            serverStop.Dispose();
        }

        [Test]
        public void MyTestMethod()
        {
            // arrange
            var r = QueryServer();
            var q = "";
            // act

            // assert
            Assert.IsTrue(false);
        }

        public void MyTestMethod2()
        {
            // arrange

            // act

            // assert
            Assert.IsTrue(false);
        }

        static readonly List<InMemRRData> records = new List<InMemRRData>()
        {
            new InMemRRData("www.test.pl", QClass.IN, QType.A, "testplname", 111, new RDataA() { Address = 0x44332211 })
        };


        private List<PwshRecord> QueryServer()
        {
            ProcessStartInfo startInfo = new ProcessStartInfo();
            startInfo.FileName = @"powershell.exe";
            startInfo.Arguments = @"-command resolve-dnsname www.google.com -server 127.0.0.1 | convertto-json";
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

        class PwshRecord
        {
            public string IP6Address { get; set; }
            public string IP4Address { get; set; }
            public string Name { get; set; }
            public int Type { get; set; }
            public int CharacterSet { get; set; }
            public int Section { get; set; }
            public int DataLength { get; set; }
            public int TTL { get; set; }
            public string Address { get; set; }
            public string IPAddress { get; set; }
            public int QueryType { get; set; }
        }

        static InMemRRData RecordA_1;

        static DnsServerIntegrationTests()
        {
            RecordA_1 = new InMemRRData("www.local-test.com", QClass.IN, QType.A, "name", 1234, new RDataA() { Address = 0x01020304 });
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
