using Arctium.Standards.Connection.Tls13;

namespace Arctium.Standards.Connection.Tls13.Messages
{
    public class ClientConfigPreSharedKey
    {
        internal PskTicketClientStoreBase ClientStore { get; private set; }

        public ClientConfigPreSharedKey(PskTicketClientStoreBase clientStore)
        {
            ClientStore = clientStore;
        }
    }
}
