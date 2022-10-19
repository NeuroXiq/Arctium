using Arctium.Standards.Connection.Tls.Tls13.API;
using Arctium.Standards.Connection.Tls.Tls13.Model;
using Arctium.Standards.Connection.Tls.Tls13.Model.Extensions;
using Arctium.Shared.Helpers;
using System.Collections.Generic;
using Arctium.Cryptography.Utils;
using System.Linq;
using System;
using Arctium.Standards.X509.X509Cert;

namespace Arctium.Standards.Connection.Tls.Tls13.API
{
    public class Tls13ServerContext
    {
        public Tls13ServerConfig Config { get; private set; }

        private PskTicketServerStoreBase pskTicketStore;

        public Tls13ServerContext(Tls13ServerConfig config, PskTicketServerStoreBase pskTicketStore)
        {
            config.ThrowIfInvalidObjectState();
            Config = config;
            this.pskTicketStore = pskTicketStore;
        }

        internal PskTicket GetPskTicket(PreSharedKeyClientHelloExtension preSharedKeyExtension,
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

        public static Tls13ServerContext DefaultUnsafe(X509CertWithKey[] certificates)
        {
            var config = Tls13ServerConfig.DefaultUnsafe(certificates);
            var context = new Tls13ServerContext(config, new PskTicketServerStoreDefaultInMemory());

            return context;
        }
    }
}
