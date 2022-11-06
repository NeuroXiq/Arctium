```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 * TLS 1.3 - Client - Supported Signature Schemes
 * 
 * How to configure Supported Signature Schemes
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

            // Client will accept only one signature scheme (config can accept more thant one)
            // If server do not support this then aborting
            context.Config.ConfigueSupportedSignatureSchemes(new SignatureScheme[] { SignatureScheme.EcdsaSecp256r1Sha256 });

            var client = new Tls13Client(context);
            var networkStream = Tls13Resources.NetworkStreamToExampleServer();



            var stream = client.Connect(networkStream, out var info);
        }
    }
}

```