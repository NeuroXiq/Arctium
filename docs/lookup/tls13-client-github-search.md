```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 * 
 * This code demonstrates how to connect and search www.github.com
 * It uses Arctium TLS 1.3 Client for connection with following extensions:
 *  - ALPN
 *  - Server Name
 */


using Arctium.Standards.Connection.Tls.Tls13.API;
using Arctium.Standards.Connection.Tls.Tls13.API.Extensions;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Web;

namespace ConsoleAppTest
{
    class SearchResult
    {
        public string PageName;
        public string PageUrl;

        public SearchResult(string url, string description)
        {
            this.Description = description;
            PageUrl = url;
        }

        public string Description { get; }
    }

    internal class MainProgram
    {
        static Tls13ClientContext tlsClientContext;
        static Tls13Client githubTlsClient;
        static IPAddress GithubIP;
        const string GithubHostName = "github.com";


        static MainProgram()
        {
            /* Configure TLS 1.3 client */

            tlsClientContext = Tls13ClientContext.DefaultUnsafe();

            var hostNameExtension = new ExtensionClientConfigServerName(GithubHostName);
            var alpnExtension = new ExtensionClientALPNConfig();
            alpnExtension.Add(ALPNProtocol.HTTP_1_1);

            tlsClientContext.Config.ConfigureExtensionServerName(hostNameExtension);
            tlsClientContext.Config.ConfigureExtensionALPN(alpnExtension);

            githubTlsClient = new Tls13Client(tlsClientContext);

            GithubIP = Dns.GetHostAddresses("www.github.com")[0];
        }   


        static void HelloText()
        {
            Console.WriteLine("Arctium TLS 1.3 example github browser. Connects To github, shows search results, shows specific result");
            Console.WriteLine("Usage, type text and click enter to search github by Arctium TLS 1.3 Client Connection");
            Console.WriteLine("For example type 'Arctium'");
        }

        public static void Main()
        {
            HelloText();

            while (true)
            {
                Console.Write(">> ");
                string input = Console.ReadLine();

                var htmlContent = SearchGithub(input);
                var results = ParseSerchResults(htmlContent);
                ShowResults(results);
                Console.WriteLine("================ End of results ================");
            }
        }

        private static void ShowResults(List<SearchResult> results)
        {
            foreach (var result in results)
            {
                Console.WriteLine("href: {0}", result.PageUrl);
                Console.WriteLine("description: {0}", result.Description);
            }
        }

        private static List<SearchResult> ParseSerchResults(string htmlContent)
        {
            List<SearchResult> results = new List<SearchResult>();

            string repoListItem = "repo-list-item";
            int start = htmlContent.IndexOf(repoListItem);
            while (start > -1)
            {
                int hrefStart = htmlContent.IndexOf("href=\"");
                int hrefEnd = htmlContent.IndexOf("\"", hrefStart + 6);
                string href = htmlContent.Substring(hrefStart + 6, hrefEnd - hrefStart - 6);

                string descriptionTag = "class=\"mb-1\">";
                int descriptionStart = htmlContent.IndexOf(descriptionTag, start);
                int descriptionEnd = htmlContent.IndexOf("</p>", descriptionStart);
                string description = htmlContent.Substring(descriptionStart + descriptionTag.Length, descriptionEnd - (descriptionStart + descriptionTag.Length));

                start = htmlContent.IndexOf(repoListItem, start + repoListItem.Length);

                results.Add(new SearchResult(href, description));
            }

            return results;
        }

        public static string SearchGithub(string searchText)
        {
            // prepare HTTP GET request
            string encodedSearchText = HttpUtility.UrlEncode(searchText);
            string searchUrl = $"/search?q={encodedSearchText}";

            // Open TLS 1.3 connection to github
            var tlsStream = ConnectToGithub();

            var reqBuilder = new StringBuilder();
            reqBuilder.AppendLine($"GET {searchUrl} HTTP/1.1");
            reqBuilder.AppendLine("Host: github.com");
            reqBuilder.AppendLine("Accept: */*");
            reqBuilder.AppendLine("");

            var getRequest = reqBuilder.ToString();
            var getRequestBytes = Encoding.ASCII.GetBytes(getRequest);

            // Send HTTP Get request by TLS 1.3
            tlsStream.Write(getRequestBytes);

            string result = string.Empty;
            byte[] readBuffer = new byte[1024];
            bool headerLoaded = false;
            int alreadyLoaded = 0;

            // load github chunked GET response
            // if not chunked then fails because I implemented this when 
            // response was chunked
            while (true)
            {
                // Read data by TLS 1.3
                int count = tlsStream.Read(readBuffer);
                alreadyLoaded += count;

                string partOfResponse = Encoding.ASCII.GetString(readBuffer, 0, count);
                result += partOfResponse;

                if (headerLoaded)
                {
                    // all chunks loaded?
                    if (result.IndexOf("\r\n\r\n") != result.LastIndexOf("\r\n\r\n"))
                    {
                        break;
                    }
                }

                if (!headerLoaded)
                {
                    bool isHeaderLoaded = result.Contains("\r\n\r\n");

                    if (isHeaderLoaded)
                    {
                        headerLoaded = true;
                        if (!result.ToLower().Contains("transfer-encoding: chunked"))
                        {
                            throw new InvalidCastException(
                                "This may be deprecated code. When implemented, github respond was chunked. " +
                                "Code need to be updated");
                        }
                    }
                }
            }

            // everything is loaded
            // parse chunked response
            string htmlContent = "";
            int chunkLenStart  = result.IndexOf("\r\n\r\n") + 4;
            var chunkedResponse = result.Substring(chunkLenStart).Split("\r\n");

            for (int i = 1; i < chunkedResponse.Length; i += 2)
            {
                // in this example I do not even care abote chunk length,
                // just take each second line skipping chunk length
                htmlContent += chunkedResponse[i];
            }

            return htmlContent;
        }

        private static Tls13Stream ConnectToGithub()
        {
            var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
            socket.Connect(GithubIP, 443);
            var networkStream = new NetworkStream(socket);

            var tlsStream = githubTlsClient.Connect(networkStream);

            return tlsStream;
        }
    }
}
```