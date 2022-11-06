```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 * TLS 1.3 - Client - GREASE
 * 
 * How to configure GREASE
 * 
 * Client can enable/disable GREASE extension
 * 
 */


using Arctium.Standards.Connection.Tls.Tls13.API;
using Arctium.Standards.Connection.Tls.Tls13.API.APIModel;
using Arctium.Standards.Connection.Tls.Tls13.API.Extensions;
using Arctium.Standards.Connection.Tls.Tls13.API.Messages;
using System.Net.Sockets;
using System.Text;

namespace ConsoleAppTest
{


    internal class MainProgram
    {
        static void Main()
        {
            var context = Tls13ClientContext.DefaultUnsafe();

            // diable GREASE
            context.Config.ConfigureGREASE(null);

            // enable with default GREASE
            context.Config.ConfigureGREASE(new ExtensionClientConfigGREASE());

            // or custom number of GREASE values to inject
            var config = new ExtensionClientConfigGREASE(cipherSuitesCount: 5, extensionsCount: 1, supportedGroupsCount: 2);
            context.Config.ConfigureGREASE(config);

            var client = new Tls13Client(context);

            var networkStream = Tls13Resources.NetworkStreamToExampleServer();
            var stream = client.Connect(networkStream, out var info1);

            // ready to go
        }

    }
}

```