```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 * TLS 1.3 - Client - Supported Group
 * 
 * How to configure Supported Group
 * 
 */


using Arctium.Standards.Connection.Tls.Tls13.API;
using Arctium.Standards.Connection.Tls.Tls13.API.Extensions;
using System.Net.Sockets;

namespace ConsoleAppTest
{

    internal class MainProgram
    {
        static void Main()
        {
            var context = Tls13ClientContext.DefaultUnsafe();

            // client will only use following groups
            // in key exchange. If server not support then client will abort.
            // So in this example client support is very low
            // it supports only x25519 and nothing else
            var groupsConfig = new ExtensionClientConfigSupportedGroups(new[] { NamedGroup.X25519, });
            context.Config.ConfigueExtensionSupportedGroups(groupsConfig);

            var client = new Tls13Client(context);
            var networkStream = Tls13Resources.NetworkStreamToExampleServer();



            var stream = client.Connect(networkStream, out var info);

            Console.WriteLine("Negotiated group: {0}", info.KeyExchangeNamedGroup.Value.ToString());
            /*
             * [OUTPUT]:
             * Negotiated group: X25519
             */
        }
    }
}

```