```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 * TLS 1.3 - Client - ServerName
 * 
 * How to configure Server Name 
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
        static void Main()
        {
            var context = Tls13ClientContext.DefaultUnsafe();

            var hostNameString = "github.com";
            context.Config.ConfigureExtensionServerName(new ExtensionClientConfigServerName(hostNameString));

            var client = new Tls13Client(context);
            var networkStream = Tls13Resources.NetworkStreamToExampleServer();

            var stream = client.Connect(networkStream, out var info);

            Console.WriteLine("Server supports 'server name': {0}", info.ExtensionResultServerName);

            /*
             * [EXAMPLE OUTPUT]
             * > Server supports 'server name': True
             */

        }
    }
}

```