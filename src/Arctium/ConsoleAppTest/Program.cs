using Arctium.Cryptography.HashFunctions.Hashes;
using Arctium.Shared.Helpers.Buffers;
using System.Net.Security;
using System.Text;
using System.Net.Quic;
using System.Runtime.Versioning;
using System.Net;
using System.Net.Sockets;
using System.Xml;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.Net.Http.Headers;
using Arctium.Standards.ASN1.Serialization.X690;
using Arctium.Standards.Connection.QUICv1;
using System.Xml.Serialization;

namespace Program
{
    [RequiresPreviewFeaturesAttribute]
    class Program
    {
        static void Main()
        {
            // Main2().Wait();
            // Console.ReadLine();
            //Task.Factory.StartNew(() => { ListenTCP(); });
            Task.Factory.StartNew(() =>
            {
                try
                {
                    ListenUDP2().Wait();
                    // ListenUDP();
                    //TestUDPRecv();
                }
                catch (Exception e)
                {
                    throw e;
                    // throw e.InnerException;
                }
            });

            // Task.Factory.StartNew(TestUDPRecv);
            // Task.Factory.StartNew(() => { TestSendUDP(); });
            //Task.Factory.StartNew(() => MsQuicClient().Wait());

            Console.ReadLine();
        }

        private static void TestUDPRecv()
        {
            Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

            s.Bind(new IPEndPoint(IPAddress.Any, 443));

            // var endpoint = new IPEndPoint(IPAddress.Any, 0) as EndPoint;
            // // s.Receive(new byte[443]);
            // // s.ReceiveFrom(new byte[1024], 0, 1024, SocketFlags.None, ref endpoint);

            var sender = new IPEndPoint(IPAddress.Any, 443) as EndPoint;
            byte[] buf = new byte[2 * 1024];

            while (true)
            {
                var len = s.ReceiveFrom(buf, ref sender);
                Console.WriteLine("LEN"  + len);
                if (len == 0) { Thread.Sleep(1000); continue; }
                s.SendTo(buf, sender);
                Console.WriteLine(len);
                Console.WriteLine("RECV TEST: ");
                MemDump.HexDump(buf, 0, len);
            }
            
            // s.ReceiveFromAsync(
            Debugger.Break();
        }

        private static void TestSendUDP()
        {
            Thread.Sleep(1000);
            UdpClient listener = new UdpClient(12324);
            IPEndPoint groupEP = new IPEndPoint(IPAddress.Any, 0);
            listener.Connect(new IPEndPoint(IPAddress.Loopback, 443));
            
            while (true)
            {
                Console.WriteLine(  "sending");
                listener.Send(new byte[] { 1 });
                Thread.Sleep(100);
            }
            
        }

        private static async Task ListenUDP2()
        {
            QuicSocketServer srv = new QuicSocketServer(IPAddress.Parse("127.0.0.1"), 443);

            while (true)
            {
                await srv.ProcessNextUdp();
            }

            // var result = await srv.ListenForConnectionAsync();

            Console.Read();
        }

        private static void ListenUDP()
        {
            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            socket.Bind(new IPEndPoint(IPAddress.Loopback, 443));
            byte[] b = new byte[16 * 1024];
            var client = new IPEndPoint(IPAddress.Any, 0) as EndPoint;
            while (true)
            {
                socket.ReceiveFrom(b, SocketFlags.None, ref client);
                socket.SendTo(b, client);
            }
        }

        static void ListenTCP()
        {
            Socket s = new Socket(SocketType.Stream, ProtocolType.Tcp);
            s.Bind(new IPEndPoint(IPAddress.Loopback, 443));
            s.Listen(1234);

            while (true)
            {
                var client = s.Accept();

                Task.Factory.StartNew((socket) =>
                {
                    var c = socket as Socket;
                    var stream = new NetworkStream(c);
                    var ssl = new SslStream(stream);
                    var cert = GetCertificateFromStore("localhost");

                    ssl.AuthenticateAsServer(cert);

                    while (true)
                    {
                        string content = "Hello world!<img src=\"/asdf\"/><script src=\"/script.js\" />";
                        var q = $@"
HTTP/1.1 200 OK
Date: Sun, 10 Oct 2010 23:26:07 GMT
Server: Apache/2.2.8 (Ubuntu) mod_ssl/2.2.8 OpenSSL/0.9.8g
Last-Modified: Sun, 26 Sep 2010 22:04:35 GMT
ETag: ""45b6-834-49130cc1182c0""
Accept-Ranges: bytes
Content-Length:{content.Length}
Content-Type: text/html
alt-svc: h3="":443""; ma=93600

{content}";
                        q = q.TrimStart('\r', '\n');
                        try
                        {
                            byte[] b = new byte[1024];
                            ssl.Read(b);
                            // c.Receive(b);
                            // Console.WriteLine(Encoding.ASCII.GetString(b));
                            var httpres = q;
                            ssl.Write(Encoding.ASCII.GetBytes(httpres));
                            // c.Send(Encoding.ASCII.GetBytes(httpres));
                        }
                        catch (Exception e)
                        {
                            break;

                        }
                    }
                }, client);
            }







            /*
             HTTP/2 200 
             ...
             alt-svc: h3-27=":443"; ma=86400, h3-28=":443"; ma=86400, h3-29=":443"; ma=86400
             */

        }

        static async Task Main2()
        {
            var serverConnectionOptions = new QuicServerConnectionOptions
            {
                // Used to abort stream if it's not properly closed by the user.
                // See https://www.rfc-editor.org/rfc/rfc9000#section-20.2
                DefaultStreamErrorCode = 0x0A, // Protocol-dependent error code.

                // Used to close the connection if it's not done by the user.
                // See https://www.rfc-editor.org/rfc/rfc9000#section-20.2
                DefaultCloseErrorCode = 0x0B, // Protocol-dependent error code.

                // Same options as for server side SslStream.
                ServerAuthenticationOptions = new SslServerAuthenticationOptions
                {
                    // List of supported application protocols, must be the same or subset of QuicListenerOptions.ApplicationProtocols.
                    ApplicationProtocols = new List<SslApplicationProtocol>() { SslApplicationProtocol.Http3 },
                    // Server certificate, it can also be provided via ServerCertificateContext or ServerCertificateSelectionCallback.
                    ServerCertificate = null
                }
            };

            // Initialize, configure the listener and start listening.
            var listener = await QuicListener.ListenAsync(new QuicListenerOptions
            {
                // Listening endpoint, port 0 means any port.
                ListenEndPoint = new IPEndPoint(IPAddress.Loopback, 1234),
                // List of all supported application protocols by this listener.
                ApplicationProtocols = new List<SslApplicationProtocol>() { SslApplicationProtocol.Http3 },
                // Callback to provide options for the incoming connections, it gets called once per each connection.
                ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(serverConnectionOptions)
            });

            // Accept and process the connections.
            while (true)
            {
                // Accept will propagate any exceptions that occurred during the connection establishment,
                // including exceptions thrown from ConnectionOptionsCallback, caused by invalid QuicServerConnectionOptions or TLS handshake failures.
                var connection = await listener.AcceptConnectionAsync();
                // connection.AcceptInboundStreamAsync();
                var b = "";

                // Process the connection...
            }

        }


        static async Task MsQuicServer()
        {
            
        }

        static async Task MsQuicClient()
        {
            // First, check if QUIC is supported.
            if (!QuicConnection.IsSupported)
            {
                Console.WriteLine("QUIC is not supported, check for presence of libmsquic and support of TLS 1.3.");
                return;
            }

            // This represents the minimal configuration necessary to open a connection.
            var clientConnectionOptions = new QuicClientConnectionOptions
            {
                // End point of the server to connect to.
                RemoteEndPoint = new IPEndPoint(IPAddress.Loopback, 443),

                // Used to abort stream if it's not properly closed by the user.
                // See https://www.rfc-editor.org/rfc/rfc9000#section-20.2
                DefaultStreamErrorCode = 0x0A, // Protocol-dependent error code.

                // Used to close the connection if it's not do ne by the user.
                // See https://www.rfc-editor.org/rfc/rfc9000#section-20.2
                DefaultCloseErrorCode = 0x0B, // Protocol-dependent error code.

                // Optionally set limits for inbound streams.
                MaxInboundUnidirectionalStreams = 10,
                MaxInboundBidirectionalStreams = 100,

                // Same options as for client side SslStream.
                ClientAuthenticationOptions = new SslClientAuthenticationOptions
                {
                    // List of supported application protocols.
                    ApplicationProtocols = new List<SslApplicationProtocol>() { SslApplicationProtocol.Http3 }
                }
            };

            // Initialize, configure and connect to the server.
            var connection = await QuicConnection.ConnectAsync(clientConnectionOptions);

            Console.WriteLine($"Connected {connection.LocalEndPoint} --> {connection.RemoteEndPoint}");

            // Open a bidirectional (can both read and write) outbound stream.
            var outgoingStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);

            // Work with the outgoing stream ...

            // To accept any stream on a client connection, at least one of MaxInboundBidirectionalStreams or MaxInboundUnidirectionalStreams of QuicConnectionOptions must be set.
            while (true)
            {
                // Accept an inbound stream.
                var incomingStream = await connection.AcceptInboundStreamAsync();

                // Work with the incoming stream ...
            }

            // Close the connection with the custom code.
            await connection.CloseAsync(0x0C);

            // Dispose the connection.
            await connection.DisposeAsync();
        }   


        private static X509Certificate2 GetCertificateFromStore(string certName)
        {

            // Get the certificate store for the current user.
            X509Store store = new X509Store(StoreLocation.CurrentUser);
            try
            {
                store.Open(OpenFlags.ReadOnly);

                // Place all certificates in an X509Certificate2Collection object.
                X509Certificate2Collection certCollection = store.Certificates;
                // If using a certificate with a trusted root you do not need to FindByTimeValid, instead:
                // currentCerts.Find(X509FindType.FindBySubjectDistinguishedName, certName, true);
                X509Certificate2Collection currentCerts = certCollection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);
                X509Certificate2Collection signingCert = currentCerts.Find(X509FindType.FindBySubjectDistinguishedName, certName, false);
                return currentCerts[0];
                // Return the first certificate in the collection, has the right name and is current.
                return signingCert[0];
            }
            finally
            {
                store.Close();
            }
        }
    }
}