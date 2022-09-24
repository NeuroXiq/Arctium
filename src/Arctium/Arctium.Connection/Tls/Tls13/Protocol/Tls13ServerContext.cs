using Arctium.Connection.Tls.Tls13.API;
using Arctium.Connection.Tls.Tls13.Model;
using Arctium.Connection.Tls.Tls13.Model.Extensions;
using Arctium.Shared.Helpers;
using System.Collections.Generic;

namespace Arctium.Connection.Tls.Tls13.Protocol
{
    class Tls13ServerContext
    {
        public struct PskTicket
        {
            public byte[] Ec_or_Ecdhe;
            public byte[] ResumptionMasterSecret;
            public byte[] Ticket;
            public byte[] TicketNonce;
            public string HashFunctionName;
            public byte[] BinderKey;

            public PskTicket(byte[] ec_or_Ecdhe,
                byte[] ticket,
                byte[] nonce,
                byte[] resumptionMastserSecret,
                string hashFunctionName,
                byte[] binderKey)
            {
                Ec_or_Ecdhe = ec_or_Ecdhe;
                Ticket = ticket;
                TicketNonce = nonce;
                ResumptionMasterSecret = resumptionMastserSecret;
                HashFunctionName = hashFunctionName;
                BinderKey = binderKey;
            }
        }

        public Tls13ServerConfig Config { get; private set; }

        public List<PskTicket> PskTickets { get; private set; }

        public Tls13ServerContext(Tls13ServerConfig config)
        {
            Config = config;
            PskTickets = new List<PskTicket>();
        }

        public PskTicket GetPskTicket(PreSharedKeyClientHelloExtension preSharedKeyExtension,
            string selectedCipherSuiteHashFunctionName,
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
                        selectedCipherSuiteHashFunctionName == PskTickets[j].HashFunctionName)
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

        public void SavePskTicket(byte[] ec_or_ecdhe,
            byte[] resumptionMasterSecret,
            byte[] ticket,
            byte[] nonce,
            string hashFunctionName,
            byte[] binderKey)
        {
            this.PskTickets.Add(new PskTicket(ec_or_ecdhe, ticket, nonce, resumptionMasterSecret, hashFunctionName, binderKey));
        }
    }
}
