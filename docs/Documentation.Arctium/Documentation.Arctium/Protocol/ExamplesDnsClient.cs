using Arctium.Protocol.DNS;

namespace Documentation.Arctium.Protocol
{
    public class ExamplesDnsClient
    {
        public static void Startup()
        {
            Console.WriteLine("Examples - DNS Client");
            DnsResolver resolver = new DnsResolver();

            var result = resolver.ResolveHostNameToHostAddressAsync("www.google.com").Result;

            Console.WriteLine(string.Join(", ", result.Select(t => t.ToString())));
        }
    }
}
