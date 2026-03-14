using Arctium.Protocol.DNS;
using Arctium.Protocol.DNS.Model;
using Arctium.Protocol.DNS.Server;
using System.Security.Cryptography.X509Certificates;

namespace Documentation.Arctium.Protocol
{
    public class ExamplesDnsServer
    {
        public static void Startup()
        {
            Console.WriteLine("Examples - DNS Server");

            AllExamples();
        }

        static void AllExamples()
        {
            // comment/uncomment examples in specific to run it

            Example1_DoHConfiguration();
        }

        public static void Example1_DoHConfiguration()
        {
            var options = CreateDefaultOptions();

            // DoH configuration

            options.AddMessageIO_DoH(
                "https://localhost/",
                "/dns-query-get",
                "/dns-query-post",
                GetCertificate());

            var server = new DnsServer(options);

            server.Start();
            Thread.Sleep(1000 * 1000);

            // now it works with get/pos
            // for example:
            // curl 'https://localhost/dns-query-get?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE'
            //  -method GET
            //  -headers @{'content-type' = 'application/dns-message'; 'accept'='application/dns-message'}

            // for windows only
            // powershell will generate test certificate:
            // dotnet dev-certs https --trust
        }

        static DnsServerOptions CreateDefaultOptions()
        {
            var recordsDb = new InMemoryDnsServerMasterFiles();
            recordsDb.Add("pl.test", QClass.IN, QType.SOA, 12345,
                new RDataSOA()
                {
                    Minimum = 12342,
                    Expire = 12345,
                    MName = "test.soa",
                    Refresh = 1234,
                    Retry = 1234,
                    RName = "mail.pl.test",
                    Serial = 1234
                });

            recordsDb.AddIN("pl.arctium.example1", QType.A, 1234, new RDataA("111.222.333.444"));
            var options = DnsServerOptions.CreateDefault(recordsDb);

            return options;
        }

        static X509Certificate2 GetCertificate()
        {
            using var store = new X509Store(StoreName.My,
                StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);

            var certificate = store.Certificates.Find(
                X509FindType.FindBySubjectName,
                "localhost",
                validOnly: true)
            .OfType<X509Certificate2>()
            .FirstOrDefault();

            if (certificate == null) throw new Exception("no cerficate found, correct this code or return other certificate by manual code");

            return certificate;
        }
    }
}
