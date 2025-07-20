namespace Arctium.Standards.Connection.Tls13
{
    public abstract class PskTicketClientStoreBase
    {
        public abstract void Save(PskTicket ticket);

        public abstract PskTicket[] GetToSendInClientHello();
    }
}
