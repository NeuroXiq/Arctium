using Arctium.Shared.Other;
using Arctium.Protocol.Tls13;

namespace Arctium.Protocol.Tls13.Messages
{
    /// <summary>
    /// 
    /// </summary>
    public class ServerConfigPreSharedKey
    {
        public PskTicketServerStoreBase ServerStore { get; private set; }
        public int NewSessionTicketsCount { get; private set; }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="serverStore"></param>
        /// <param name="newSessionTicketsCount">Count of NewSessionTicket to issue for new connection</param>
        public ServerConfigPreSharedKey(PskTicketServerStoreBase serverStore, int newSessionTicketsCount)
        {
            Validation.NotNull(serverStore, nameof(serverStore));
            Validation.NumberInRange(newSessionTicketsCount, 0, 1000, nameof(newSessionTicketsCount),
                "max value is 1000 not because of standard but limit by Arctium implementation (it may change in future)");

            ServerStore = serverStore;
            NewSessionTicketsCount = newSessionTicketsCount;
        }
    }
}
