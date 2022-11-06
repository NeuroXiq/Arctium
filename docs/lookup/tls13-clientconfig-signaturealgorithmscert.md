```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 * TLS 1.3 - Client - Signature Algorithms Cert
 * 
 * How to configure Signature Algorithms Cert
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

            // what to send in extension?
            var signAlgoCertConfig = new ExtensionClientConfigSignatureAlgorithmsCert(new SignatureScheme[]
            {
                SignatureScheme.EcdsaSecp256r1Sha256,
                SignatureScheme.EcdsaSecp384r1Sha384
            });

            // configure 
            context.Config.ConfigureExtensionSignatureAlgorithmsCert(signAlgoCertConfig);
            
            var client = new Tls13Client(context);
            var networkStream = Tls13Resources.NetworkStreamToExampleServer();

            var stream = client.Connect(networkStream, out var info);

            // ready to go
        }
    }
}

```