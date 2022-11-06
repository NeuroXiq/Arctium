```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 * TLS 1.3 - Oid Filters
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


            // byte arrays must be valid DER encoded bytes
            // in this example they are not valid values,
            var filters = new ExtensionServerConfigOidFilters.OidFilter[]
            {
                new ExtensionServerConfigOidFilters.OidFilter(new byte[] { 1, 2, 3 }, new byte[] { 1, 1, 2, 2 }),
                new ExtensionServerConfigOidFilters.OidFilter(new byte[] { 1, 2 }, new byte[] { 1, 1, 2, 2, 3, 3 }),
                new ExtensionServerConfigOidFilters.OidFilter(new byte[] { 1, }, new byte[] { 1, 1, 2, 2, 3, 3 })
            };

            /* Configuration of Oid Filters */
            // if config enabled then server will sent this filters during client authentication
            serverContext.Config.ConfigureExtensionOidFilters(new ExtensionServerConfigOidFilters(filters));

            var tlsServer = new Tls13Server(serverContext);
            var networkStream = AcceptSocketNetworkStream();
            var tlsStream = tlsServer.Accept(networkStream, out var connectionInfo);


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