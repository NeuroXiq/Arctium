```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 * TLS 1.3 - Client - Cipher Suites
 * 
 * How to configure cipher suites
 * 
 */


using Arctium.Standards.Connection.Tls.Tls13.API;
using System.Net.Sockets;

namespace ConsoleAppTest
{

    internal class MainProgram
    {
        static Socket socket;

        static void Main()
        {
            var context = Tls13ClientContext.DefaultUnsafe();

            // configure cipher suite
            // client will only sue specified cipher, if server not support client will abort
            context.Config.ConfigueCipherSuites(new[] { CipherSuite.TLS_AES_256_GCM_SHA384 });

            var client = new Tls13Client(context);
            var networkStream = Tls13Resources.NetworkStreamToExampleServer();

            var stream = client.Connect(networkStream, out var info);

            Console.WriteLine("Negotiated cipher: {0}", info.CipherSuite.ToString());
            /*
             * [OUTPUT]:
             * Negotiated cipher: TLS_AES_256_GCM_SHA384
             */
        }
    }
}

```