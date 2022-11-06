```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 * TLS 1.3 - Client - Pre Shared Key
 * 
 * How to configure Pre Shared Key
 * 
 * By Default arctium use In memory Pre Shared Key implementation anyway.
 * Use custom if want to custom behavious e.g. remove ticked based on some policy
 * save and get from database etc.
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
    class PSKTicketStore : PskTicketClientStoreBase
    {
        List<PskTicket> tickets = new List<PskTicket>();

        public override PskTicket[] GetToSendInClientHello()
        {
            // what ticket to get to send in client hello?
            // can return empty list
            // 
            // this should somehow be connected with specific website
            // e.g. tickets for github are other than ticket to stackoverflow etc.
            // so should not mix them. 
            // this method does not do this

            return tickets.ToArray();
        }

        public override void Save(PskTicket ticket)
        {
            // it is invoked when received from server NewSessionTicket message
            tickets.Add(ticket);
        }
    }

    class PSKConfig : ClientConfigPreSharedKey
    {
        public PSKConfig(PskTicketClientStoreBase clientStore) : base(clientStore)
        {
        }
    }

    internal class MainProgram
    {
        static void Main()
        {
            var context = Tls13ClientContext.DefaultUnsafe();

            var pskStore = new PSKTicketStore();
            var pskConfig = new PSKConfig(pskStore);

            context.Config.ConfigurePreSharedKey(pskConfig);

            // use same client instance for multiple connection 
            // to use same tickets store
            var client = new Tls13Client(context);
            
            var networkStream1 = Tls13Resources.NetworkStreamToExampleServer();
            var stream1 = client.Connect(networkStream1, out var info1);

            // need read some application data first something to get newsessiontickets
            // works depends on sever:
            // Tested with google: google shows info2/info3 as resumed.
            // Tested with github: don't show as resumed (maybe invalid request?) but doesn't really
            // matter because example shows how ticket works


            Task.Factory.StartNew(() => { Get(stream1); });
            Thread.Sleep(700);

            var networkStream2 = Tls13Resources.NetworkStreamToExampleServer();
            var stream2 = client.Connect(networkStream2, out var info2);

            Task.Factory.StartNew(() => { Get(stream2); });
            Thread.Sleep(700);

            var networkStream3 = Tls13Resources.NetworkStreamToExampleServer();
            var stream3 = client.Connect(networkStream3, out var info3);
            Task.Factory.StartNew(() => { Get(stream3); });


            Console.WriteLine("session resumed / info1: {0}", info1.IsPskSessionResumption);
            Console.WriteLine("session resumed / info2: {0}", info2.IsPskSessionResumption);
            Console.WriteLine("session resumed / info3: {0}", info3.IsPskSessionResumption);

            // ready to go
        }

        static void Get(Tls13Stream stream)
        {
            string get = "GET / HTTP/1.1\r\n" +
                "Accept: */*\r\n\r\n";

            stream.Write(Encoding.ASCII.GetBytes(get));
            stream.Read(new byte[100]);
        }

    }
}

```