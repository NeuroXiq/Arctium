using Arctium.Protocol.DNS;

namespace Documentation.Arctium.Protocol
{
    public class ExamplesDnsClient
    {
        public static void Startup()
        {
            Console.WriteLine("Examples - DNS Client");
            DnsResolver resolver = new DnsResolver();

            Example1();
            Example2();
        }

        /// <summary>
        /// Simple resolve
        /// This example shows, how to resolve name to IP address
        /// using basic method and default options
        /// </summary>
        public static void Example1()
        {
            var resolver = new DnsResolver();
            var result = resolver.ResolveHostNameToHostAddressAsync("www.google.com").Result;

            Console.WriteLine("Example 1");
            Console.WriteLine(string.Join("\r\n", result.Select(t => "* " + t.ToString())));

            // result:
            // Examples - DNS Client
            // Example 1
            // * 142.250.109.106
            // * 142.250.109.103
            // * 142.250.109.104
            // * 142.250.109.147
            // * 142.250.109.99
            // * 142.250.109.105
            // * 2001:4860:4828:7700::
            // * 2001:4860:4827:7700::
            // * 2001:4860:482d:7700::
            // * 2001:4860:482c: 7700::
            // * 2001:4860:4826:7700::
            // * 2001:4860:482a: 7700::
            // * 2001:4860:4829:7700::
            // * 2001:4860:482b: 7700::
        }

        /// <summary>
        /// DoH (Dns over HTTPS)
        /// This example shows how to configure
        /// dns resolve to use DoH mode
        /// 
        /// </summary>
        public static void Example2()
        {
            var options = DnsResolverOptions.CreateDefault();
            options.SetClientMessageIO_DoH("https://dns.google/dns-query", DnsClientMessageIO_Rfc8484DoH.HttpMethod.Post);

            var resolver = new DnsResolver();
            var result = resolver.ResolveHostNameToHostAddressAsync("www.google.com").Result;

            Console.WriteLine("Example2 - Resolve dns over HTTPS using google dns server");
            Console.WriteLine(string.Join("\r\n", result.Select(t => "* " + t.ToString())));

            // result:
            // Example2 - Resolve dns over HTTPS using google dns server
            // * 142.250.109.104
            // * 142.250.109.99
            // * 142.250.109.106
            // * 142.250.109.105
            // * 142.250.109.103
            // * 142.250.109.147
            // * 2a00: 1450:4025:800::6a
            // * 2a00: 1450:4025:800::63
            // * 2a00: 1450:4025:800::93
            // * 2a00: 1450:4025:800::67
        }
    }
}
