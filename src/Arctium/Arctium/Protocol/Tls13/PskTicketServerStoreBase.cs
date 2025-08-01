using Arctium.Cryptography.Utils;

namespace Arctium.Protocol.Tls13
{
    public abstract class PskTicketServerStoreBase
    {
        public abstract void SaveTicket(PskTicket ticketToSave);

        public abstract PskTicket GetTicket(byte[][] availableTicketsFromClient, HashFunctionId hashFunctionId);
    }
}
