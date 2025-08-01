using Arctium.Shared.Exceptions;
using System.Collections.Generic;
using Arctium.Protocol.Tls13Impl.Model.Extensions;

namespace Arctium.Protocol.Tls13Impl.Model
{
    class NewSessionTicket
    {
        public uint TicketLifetime { get; private set; }
        public uint TicketAgeAdd { get; private set; }
        public byte[] TicketNonce { get; private set; }
        public byte[] Ticket { get; private set; }
        public List<Extension> Extensions { get; private set; }

        public NewSessionTicket(uint ticketLifetime, uint ticketAgeAdd, byte[] ticketNonce, byte[] ticket, Extension[] extensions)
        {
            if (!Validate(ticketLifetime, ticketAgeAdd, ticketNonce, ticket, extensions))
                throw new ArctiumExceptionInternal("One or more invalid values of ticket");

            TicketLifetime = ticketLifetime;
            TicketAgeAdd = ticketAgeAdd;
            TicketNonce = ticketNonce;
            Ticket = ticket;
            Extensions = new List<Extension>(extensions);
        }

        public static bool Validate(uint ticketLifetime, uint ticketAgeAdd, byte[] ticketNonce, byte[] ticket, Extension[] extensions)
        {
            if (ticketLifetime > Tls13Const.NewSessionTicket_MaxTicketLifetimeSeconds ||
                ticketNonce.Length > Tls13Const.NewSessionTicket_MaxTicketNonceLength ||
                ticket.Length < Tls13Const.NewSessionTicket_MinTicketLength ||
                ticket.Length > Tls13Const.NewSessionTicket_MaxTicketLength)
            {
                return false;
            }

            return true;
        }
    }
}
