namespace Arctium.Standards.Connection.Tls.Tls13.API.Messages
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
