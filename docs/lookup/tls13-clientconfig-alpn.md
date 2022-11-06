```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 * TLS 1.3 - Client - ALPN
 * 
 * How to configure Application Layer Protocol Negotiation
 * 
 */


using Arctium.Standards.Connection.Tls.Tls13.API;
using Arctium.Standards.Connection.Tls.Tls13.API.Extensions;
using System.Net.Sockets;
using System.Text;

namespace ConsoleAppTest
{

    internal class MainProgram
    {

        static ExtensionClientALPNConfig GetALPNConfig()
        {
            // Configuration of ALPN
            // As shown, arctium supports:
            // - standarized names by IANA (enum values)
            // - string values
            // - raw byte values
            // Variety of possible names are supported.
            // This config will sent three protocol names

            var alpnConfig = new ExtensionClientALPNConfig();

            // standarized name:
            alpnConfig.Add(ALPNProtocol.HTTP_1_0);
            alpnConfig.Add(ALPNProtocol.HTTP_1_1);

            // string name
            alpnConfig.Add("HTTP/0.9");

            // byte name
            byte[] bytes = Encoding.ASCII.GetBytes("not-standarized");
            alpnConfig.Add(bytes);

            return alpnConfig;
        }

        static void Main()
        {
            var context = Tls13ClientContext.DefaultUnsafe();


            var alpnConfig = GetALPNConfig();
            context.Config.ConfigureExtensionALPN(alpnConfig);

            var client = new Tls13Client(context);
            var networkStream = Tls13Resources.NetworkStreamToExampleServer();

            var stream = client.Connect(networkStream, out var info);

            // look for server response:

            var serverResult = info.ExtensionResultALPN;

            if (serverResult != null)
            {
                Console.WriteLine("Server ALPN selected:");

                if (ExtensionResultALPN.TryGetAsStandarizedALPNProtocol(info.ExtensionResultALPN.Protocol, out var standarizedName))
                {
                    Console.WriteLine("Standarized: {0}", standarizedName.ToString());
                }
                else
                {
                    Console.WriteLine("Not standarized: {0}", Encoding.ASCII.GetString(info.ExtensionResultALPN.Protocol));
                }
            }
            else
            {
                Console.WriteLine("Server does not support ALPN");
            }

            /*
             * [EXAMPLE OUTPUT]
             * >
             * > Server ALPN selected:
             * > Standarized: HTTP_1_1
             */

        }
    }
}

```