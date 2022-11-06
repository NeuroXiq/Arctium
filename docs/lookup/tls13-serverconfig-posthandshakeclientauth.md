```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 * TLS 1.3 - Post Handshake Client Authentication
 * For example, cURL supports (or rather underlying implementation of TLS) 
 * post handshake client auth.
 * Server can request client authentication at any time after handshake
 * multiple times if needed. See example below
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
    // This is a configuration 
    class PHClientAuth : ServerConfigPostHandshakeClientAuthentication
    {
        public override Action CertificateFromClientReceived(byte[][] certificateFromClient, List<Extension> extensions)
        {
            // parameter is a certificate from client (can be empty) and client extensions if sent with certificate
            // arctium do not validate x509 chain, so it (by default) always accept self-signed cert.
            // validation of certificate must be done here
            //
            // Actions same as for Handshake Client Auth

            return Action.Success;
        }
    }

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

            /* Configuration of post handshake client auth */
            // With this configuration server can request client authentication
            // at any time (and multiple times) after handshake, see example below
            serverContext.Config.ConfigurePostHandshakeClientAuthentication(new PHClientAuth());


            var tlsServer = new Tls13Server(serverContext);
            var networkStream = AcceptSocketNetworkStream();
            var tlsStream = tlsServer.Accept(networkStream);


            // ok, now request auth from client:
            // for example can request how many time it wants
            tlsStream.PostHandshakeClientAuthentication();
            tlsStream.PostHandshakeClientAuthentication();
            tlsStream.PostHandshakeClientAuthentication();



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