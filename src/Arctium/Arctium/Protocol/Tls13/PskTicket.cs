using Arctium.Cryptography.Utils;

namespace Arctium.Protocol.Tls13
{
    public class PskTicket
    {
        public byte[] ResumptionMasterSecret;
        public byte[] Ticket;
        public byte[] TicketNonce;
        public uint TicketLifetime;
        public uint TicketAgeAdd;
        public HashFunctionId HashFunctionId;

        public PskTicket(byte[] ticket,
            byte[] nonce,
            byte[] resumptionMastserSecret,
            uint ticketLifetime,
            uint ticketAgeAdd,
            HashFunctionId hashFunctionId)
        {
            Ticket = ticket;
            TicketNonce = nonce;
            ResumptionMasterSecret = resumptionMastserSecret;
            TicketLifetime = ticketLifetime;
            TicketAgeAdd = ticketAgeAdd;
            HashFunctionId = hashFunctionId;
        }
    }
}
