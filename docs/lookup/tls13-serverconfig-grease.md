```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 * TLS 1.3 - GREASE
 * 
 * How to enable/disable GREASE on server
 * 
 */


using Arctium.Cryptography.Utils;
using Arctium.Shared.Helpers;
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

            // disable GREASE
            serverContext.Config.ConfigureGREASE(null);

            // enable GREASE
            // can also specify how many GREASE values to inject in specific messages

            var greaseConfig = new ExtensionServerConfigGREASE(
                certReqExtensionsCountInCertRequest: 5,
                certReqSignatureAlgorithmsCertCount: 4,
                certReqSignatureAlgorithmsCount: 2,
                newSessTickExtCount: 1);

            // or use defauilt ctopr
            greaseConfig = new ExtensionServerConfigGREASE();

            serverContext.Config.ConfigureGREASE(greaseConfig);

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