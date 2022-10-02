using Arctium.Standards.Connection.Tls.Tls13.API;
using Arctium.Standards.Connection.Tls.Tls13.Model;
using Arctium.Standards.Connection.Tls.Tls13.Model.Extensions;
using Arctium.Shared.Helpers;
using System.Collections.Generic;
using Arctium.Cryptography.Utils;

namespace Arctium.Standards.Connection.Tls.Tls13.Protocol
{
    class Tls13ServerContext
    {
        public Tls13ServerConfig Config { get; private set; }

        public List<PskTicket> PskTickets { get; private set; }

        public Tls13ServerContext(Tls13ServerConfig config)
        {
            Config = config;
            PskTickets = new List<PskTicket>();
        }

        public PskTicket GetPskTicket(PreSharedKeyClientHelloExtension preSharedKeyExtension,
            HashFunctionId selectedCipherSuiteHashFunctionId,
            out int clientSelectedIndex)
        {
            clientSelectedIndex = -1;
            int serverSelected = -1;
            var clientIdentities = preSharedKeyExtension.Identities;

            for (int i = 0; i < clientIdentities.Length; i++)
            {
                for (int j = 0; j < this.PskTickets.Count; j++)
                {
                    if (MemOps.Memcmp(this.PskTickets[j].Ticket, clientIdentities[i].Identity) &&
                        selectedCipherSuiteHashFunctionId == PskTickets[j].HashFunctionId)
                    {
                        clientSelectedIndex = (int)i;
                        serverSelected = j;
                        goto _break;
                    }
                }
            }_break:

            if (clientSelectedIndex == -1)
            {
                return default(PskTicket);
            }

            return PskTickets[serverSelected];
        }

        public void SavePskTicket(byte[] resumptionMasterSecret,
            byte[] ticket,
            byte[] nonce,
            uint ticketLifetime,
            uint ticketAgeAdd,
            HashFunctionId hashFunctionId)
        {
            this.PskTickets.Add(new PskTicket(ticket, nonce, resumptionMasterSecret, ticketLifetime, ticketAgeAdd, hashFunctionId));
        }
    }
}
