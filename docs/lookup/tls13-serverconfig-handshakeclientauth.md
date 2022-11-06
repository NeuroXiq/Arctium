```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 * TLS 1.3 - Handshake Client authentication
 * Example demonstrates how to configure Handshake Client Authentication
 * Client Auth is performed during handshake, server will request client certificate
 * It can be tested with e.g. cURL (because it allows put client certificate)
 * 
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

    //
    // This methos is a configuration of client authentication during handshake
    //
    class ConfigHSClientAuth : ServerConfigHandshakeClientAuthentication
    {
        public override Action CertificateFromClientReceived(byte[][] certificateFromClient, List<Extension> extensions)
        {
            // 1. Arctium do not validate X509 Chain, so this method must validate it
            // 2. This is possible that client sent empty certificate list (list above has 0 elements)
            //    and this is fine because client may not authenticate. So can reject or continue
            // 3.  'extensions' parameter are extensions in certificate message from client

            if (certificateFromClient.Length > 0)
            {
                // client cert is always first
                // so now can decode it, do something with this bytes etc.
                var clientCertDerBytes = certificateFromClient[0];
            }

            // possible actions:

            return Action.Success;

            // actions aborting handshake:
            return Action.AlertFatalBadCertificate;
            return Action.AlertFatalCertificateExpired;
            return Action.AlertFatalCertificateRequired;
            return Action.AlertFatalCertificateUnknown;
            return Action.AlertFatalUnknownCa;
            return Action.AlertFatalUnsupportedCertificate;
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


            /* Configuration of Handshake Client Authentication */
            // When this configuration is enabled, server will send CertificateRequest
            // during handshake
            serverContext.Config.ConfigureHandshakeClientAuthentication(new ConfigHSClientAuth());

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