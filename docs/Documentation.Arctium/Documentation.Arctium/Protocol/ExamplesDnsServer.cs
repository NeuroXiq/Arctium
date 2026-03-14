using Arctium.Protocol.DNS;
using Arctium.Protocol.DNS.Model;

namespace Documentation.Arctium.Protocol
{
    public class ExamplesDnsServer
    {
        public static void Startup()
        {
            Console.WriteLine("Examples - DNS Server");
        }

        public static void Example1_DoHConfiguration()
        {
            var recordsDb = new InMemoryDnsServerMasterFiles();
            recordsDb.Add("pl.test", Arctium.Protocol.DNS.Model.QClass.IN, Arctium.Protocol.DNS.Model.QType.SOA, 12345,
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
            recordsDb.AddIN("pl.test", QType.A, 1234, new RDataA("111.222.333.444"));
            var options = DnsServerOptions.CreateDefault(recordsDb);
            options.AddMessageIO_DoH(
                "https://localhost/",
                "/dns-query-get",
                "/dns-query-post",
                GetCertificate());

            var server = new DnsServer(options);


            // for windows only
            // powershell will generate test certificate:
            // dotnet dev-certs https --trust
        }
    }
}
