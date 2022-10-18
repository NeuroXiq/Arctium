using Arctium.Standards.Connection.Tls.Tls13.API;
using Arctium.Standards.Connection.Tls.Tls13.Model;
using Arctium.Standards.Connection.Tls.Tls13.Model.Extensions;
using Arctium.Shared.Helpers;
using System.Collections.Generic;
using Arctium.Cryptography.Utils;
using System.Linq;

namespace Arctium.Standards.Connection.Tls.Tls13.Protocol
{
    class Tls13ServerContext
    {
        public Tls13ServerConfig Config { get; private set; }

        private PskTicketServerStoreBase pskTicketStore;

        public Tls13ServerContext(Tls13ServerConfig config, PskTicketServerStoreBase pskTicketStore)
        {
            Config = config;
            this.pskTicketStore = pskTicketStore;
        }

        public PskTicket GetPskTicket(PreSharedKeyClientHelloExtension preSharedKeyExtension,
            HashFunctionId selectedCipherSuiteHashFunctionId,
            out int clientSelectedIndex)
        {
            clientSelectedIndex = -1;
            var clientIdentities = preSharedKeyExtension.Identities;

            var tickets = preSharedKeyExtension.Identities.Select(identity => identity.Identity).ToArray();

            var selectedTicket = pskTicketStore.GetTicket(tickets, selectedCipherSuiteHashFunctionId);

            if (selectedTicket == null) return null;

            for (int i = 0; clientSelectedIndex == -1 && i < preSharedKeyExtension.Identities.Length; i++)
            {
                if (MemOps.Memcmp(clientIdentities[i].Identity, selectedTicket.Ticket))
                {
                    clientSelectedIndex = i;
                }
            }

            return selectedTicket;
        }

        public void SavePskTicket(byte[] resumptionMasterSecret,
            byte[] ticket,
            byte[] nonce,
            uint ticketLifetime,
            uint ticketAgeAdd,
            HashFunctionId hashFunctionId)
        {
            pskTicketStore.SaveTicket(new PskTicket(ticket, nonce, resumptionMasterSecret, ticketLifetime, ticketAgeAdd, hashFunctionId));
        }
    }
}
