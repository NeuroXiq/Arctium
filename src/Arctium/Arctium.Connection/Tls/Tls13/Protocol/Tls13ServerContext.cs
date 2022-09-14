using Arctium.Connection.Tls.Tls13.API;
using Arctium.Connection.Tls.Tls13.Model;
using System.Collections.Generic;

namespace Arctium.Connection.Tls.Tls13.Protocol
{
    class Tls13ServerContext
    {
        public struct PskTicket
        {
            public byte[] Ec_or_Ecdhe;
            public byte[] ResumptionMasterSecret;
            public NewSessionTicket Ticket;

            public PskTicket(byte[] ec_or_Ecdhe, NewSessionTicket ticket, byte[] resumptionMastserSecret)
            {
                Ec_or_Ecdhe = ec_or_Ecdhe;
                Ticket = ticket;
                ResumptionMasterSecret = resumptionMastserSecret;
            }
        }

        public Tls13ServerConfig Config { get; private set; }

        public List<PskTicket> PskTickets { get; private set; }

        public Tls13ServerContext(Tls13ServerConfig config)
        {
            Config = config;
            PskTickets = new List<PskTicket>();
        }
    }
}
