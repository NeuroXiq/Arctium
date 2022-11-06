```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 * TLS 1.3 - Client - Key Share
 * 
 * How to configure Key Share
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

            // what does it mean?
            // Client will generate private-key public key pairs
            // and send it to server for all groups specified here.
            // This takes time so recommended is to sent only one or two 
            // groups to no waste time on calculations
            // In this example client will compute two keys for x25519 and x448
            var keyshareConfig = new ExtensionClientConfigKeyShare(new NamedGroup[] {  NamedGroup.X25519, NamedGroup.Xx448 });
            context.Config.ConfigueExtensionKeyShare(keyshareConfig);

            var client = new Tls13Client(context);
            var networkStream = Tls13Resources.NetworkStreamToExampleServer();



            var stream = client.Connect(networkStream, out var info);
        }
    }
}

```