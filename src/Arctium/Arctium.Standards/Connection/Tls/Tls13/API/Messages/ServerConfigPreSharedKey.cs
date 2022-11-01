using Arctium.Shared.Other;

namespace Arctium.Standards.Connection.Tls.Tls13.API.Messages
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

            this.ServerStore = serverStore;
            NewSessionTicketsCount = newSessionTicketsCount;
        }
    }
}
