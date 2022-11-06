```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 * TLS 1.3 - Client - Certificate Authorities
 * 
 * How to configure Certificate Authorities
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

            // values must be valid encoded values as specification says
            // this exampel shows invalid values, it just show how to config them
            byte[][] authorities = new byte[][]
            {
                new byte[] { 1, 2, 3 },
                new byte[]{ 3, 4, 5, 6 ,7 },
            };

            context.Config.ConfigureExtensionCertificateAuthorities(new ExtensionClientConfigCertificateAuthorities(authorities));

            var client = new Tls13Client(context);
            var networkStream = Tls13Resources.NetworkStreamToExampleServer();

            var stream = client.Connect(networkStream, out var info);

            // ready to go
        }
    }
}

```