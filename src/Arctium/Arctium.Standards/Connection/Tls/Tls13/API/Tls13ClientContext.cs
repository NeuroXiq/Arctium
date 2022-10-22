using Arctium.Cryptography.Utils;
using System;

namespace Arctium.Standards.Connection.Tls.Tls13.API
{
    public class Tls13ClientContext
    {
        public Tls13ClientConfig Config { get; private set; }

        private PskTicketClientStoreBase pskTicketStore;

        public Tls13ClientContext(Tls13ClientConfig config, PskTicketClientStoreBase ticketsStore)
        {
            config.ThrowIfInvalidState();
            Config = config;
            pskTicketStore = ticketsStore;
        }

        public void ThrowIfInvalidState()
        {
            Config.ThrowIfInvalidState();
        }

        public static Tls13ClientContext DefaultUnsave()
        {
            var config = Tls13ClientConfig.DefaultUnsafe();
            var ticketStore = new PskTicketClientStoreDefaultInMemory();

            return new Tls13ClientContext(config, ticketStore);
        }

        internal void SaveTicket(byte[] ticket,
            byte[] nonce,
            byte[] resumptionMasterSecret,
            uint lifetime,
            uint ticketAgeAdd,
            HashFunctionId hashFunctionId)
        {
            if (pskTicketStore == null) return;

            pskTicketStore.Save(new PskTicket(ticket, nonce, resumptionMasterSecret, lifetime, ticketAgeAdd, hashFunctionId));
        }

        internal PskTicket[] GetPskTickets()
        {
            return pskTicketStore.GetToSendInClientHello();
        }
    }
}
