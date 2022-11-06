```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 * TLS 1.3 - Pre Shared Key
 * * Example demonstracts how to configure PSK tickets
 * and PSK tickets store to use 
 * 
 * Arctium By Default use in-memory ticket store, so use custom config if custom behaviour is needed, 
 * or want to store in external location (for example in database)
 * 
 * Note following:
 * 1. PckTicketServerStoreBase 
 *  - abstract class to save/get issued tickets. Inheritors must somehow store tickets, e.g. in memory just in 'List<T> ..'
 *    or in database.
 *  - GetTicket method may not return any tickets - even it can always return empty list and server will work fine.
 *    Server will go with full-handshake instead of resuming session. This can be usefull if want to store
 *    ticket for certain period of time e.g. 5 minutes, 5 hours, 5 days... and later remove them
 * - Save ticket (when overriden) should somehow save ticket e.g. in database or in RAM memory (List<T> ...)
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
    class ExamplePSKStore : PskTicketServerStoreBase
    {
        List<PskTicket> inMemoryStore = new List<PskTicket>();

        public override PskTicket GetTicket(byte[][] availableTicketsFromClient, HashFunctionId hashFunctionId)
        {
            // This method can always return null and nothing is wrong with this.
            // 
            // what to do in this method:
            // client sent 'availableTicketsFromClient'
            // get all that want to use. Or return null if all not valid/expired/unrecognized/ dont want to use for any other reason
            // when empty list returned server fallback to full handshake

            // so look for any:

            foreach (var fromClient in availableTicketsFromClient)
            {
                // important note. There is only one way to compate tickets:
                // it is 'pskTicket.Ticket' byte array. So look if was saved

                var found = inMemoryStore.FirstOrDefault(inMemory => MemOps.Memcmp(inMemory.Ticket, fromClient));

                if (found != null) return found;
            }

            return null;
        }

        public override void SaveTicket(PskTicket ticketToSave)
        {
            // can also save in database
            // INSERT INTO ... VALUES (ticketToSave.Ticket, .., , ... ...)
            // example shows just in memory store.
            // so just put into the list

            inMemoryStore.Add(ticketToSave);
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

            int ticketToIssueOnNewConnection = 2;
            var pskTicketStore = new ExamplePSKStore();

            serverContext.Config.ConfigurePreSharedKey(new ServerConfigPreSharedKey(pskTicketStore, ticketToIssueOnNewConnection));



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