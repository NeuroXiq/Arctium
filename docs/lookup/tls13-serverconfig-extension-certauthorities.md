```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 * TLS 1.3 - Cert Authorities
 * 
 */


using Arctium.Standards.Connection.Tls.Tls13.API;
using Arctium.Standards.Connection.Tls.Tls13.API.APIModel;
using Arctium.Standards.Connection.Tls.Tls13.API.Extensions;
using Arctium.Standards.Connection.Tls.Tls13.API.Messages;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Web;

namespace ConsoleAppTest
{
    internal class MainProgram
    {
        static Socket socket;

        static void Main()
        {
            socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
            socket.Bind(new IPEndPoint(IPAddress.Loopback, 444));
            socket.Listen(20);

            StartServer();
        }

        static void StartServer()
        {
            var certificateWithPrivateKey = Tls13Resources.CERT_WITH_KEY_cert_rsaencrypt_2048_sha256_1;
            var serverContext = Tls13ServerContext.Default(new[] { certificateWithPrivateKey });

            // Must be valid values (encoded) as specification of extensions says.
            // this example shows invalid values. Use external tools to serialize 
            // with valid format and put here serialized bytes
            var authorities = new byte[][]
            {
                new byte[] { 1, 2, 3 },
                new byte[] { 26, 8, 9 }
            };
            var certAuthoritiesConfig = new ExtensionServerConfigCertificateAuthorities(authorities);

            /* Configuration  */
            serverContext.Config.ConfigureExtensionCertificateAuthorities(certAuthoritiesConfig);


            var tlsServer = new Tls13Server(serverContext);
            var networkStream = AcceptSocketNetworkStream();
            var tlsStream = tlsServer.Accept(networkStream);

            // read from stream, do something etc. ...
            // tlsstream.read(...)
        }

        static NetworkStream AcceptSocketNetworkStream()
        {
            var rawSocket = socket.Accept();
            return new NetworkStream(rawSocket);
        }
    }
}

```