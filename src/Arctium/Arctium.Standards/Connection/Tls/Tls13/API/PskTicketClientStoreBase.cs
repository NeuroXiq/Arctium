namespace Arctium.Standards.Connection.Tls.Tls13.API
{
    public abstract class PskTicketClientStoreBase
    {
        public abstract void Save(PskTicket ticket);

        public abstract PskTicket[] GetToSendInClientHello();
    }
}
