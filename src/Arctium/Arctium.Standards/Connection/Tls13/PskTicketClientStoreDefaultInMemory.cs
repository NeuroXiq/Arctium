using System;
using System.Collections.Generic;
using System.Linq;

namespace Arctium.Standards.Connection.Tls13
{
    public class PskTicketClientStoreDefaultInMemory : PskTicketClientStoreBase
    {
        struct TicketData
        {
            public PskTicket Ticket;
            public DateTime Expiration;

            public TicketData(PskTicket ticket, DateTime exp)
            {
                Ticket = ticket;
                Expiration = exp;
            }
        }

        List<TicketData> tickets;

        public PskTicketClientStoreDefaultInMemory()
        {
            tickets = new List<TicketData>();
        }

        public override PskTicket[] GetToSendInClientHello()
        {
            CleanUpExpired();

            return tickets.Select(tdata => tdata.Ticket).ToArray();
        }

        public override void Save(PskTicket receivedTicketFromServer)
        {
            CleanUpExpired();

            var ticketData = new TicketData(receivedTicketFromServer, DateTime.Now.AddSeconds(receivedTicketFromServer.TicketLifetime));
            tickets.Add(ticketData);
        }

        public void CleanUpExpired()
        {
            var now = DateTime.Now;
            //tickets.RemoveAll(tdata => tdata.Expiration < now);
        }
    }
}
