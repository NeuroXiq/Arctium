using Arctium.Cryptography.Utils;
using Arctium.Shared.Helpers;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Arctium.Protocol.Tls13
{
    public class PskTicketServerStoreDefaultInMemory : PskTicketServerStoreBase
    {
        class TicketInfo
        {
            public DateTime Expiration;
            public PskTicket Ticket;

            public TicketInfo(PskTicket ticket, DateTime expiration)
            {
                Ticket = ticket;
                Expiration = expiration;
            }
        }

        private readonly int MaxTicketsCount = 10 * 1000;
        long refreshCounter = 0;

        List<TicketInfo> tickets = new List<TicketInfo>();

        public override PskTicket GetTicket(byte[][] availableTicketsFromClient, HashFunctionId hashFunctionId)
        {
            var tickets = GetAvailableTickets();

            // todo implement data structure for better performance

            for (int i = 0; i < availableTicketsFromClient.Length; i++)
            {
                // just find ticket in list
                var result = tickets.FirstOrDefault(info =>
                    MemOps.Memcmp(info.Ticket.Ticket, availableTicketsFromClient[i]) &&
                    info.Ticket.HashFunctionId == hashFunctionId);

                if (result != null) return result.Ticket;
            }

            return null;
        }

        private List<TicketInfo> GetAvailableTickets()
        {
            if (tickets.Count > MaxTicketsCount)
            {
                tickets.RemoveRange(tickets.Count - 1000, 1000);
            }

            if (refreshCounter++ % 20 == 0 && tickets.Count > 0)
            {
                var tinfo = tickets[0];

                if (tinfo.Expiration < DateTime.Now)
                {
                    tickets.RemoveAll(info => info.Expiration < DateTime.Now);
                }
            }

            return tickets;
        }

        public override void SaveTicket(PskTicket ticketToSave)
        {
            var expiration = DateTime.Now.AddSeconds(ticketToSave.TicketLifetime);

            tickets.Add(new TicketInfo(ticketToSave, expiration));
        }
    }
}
