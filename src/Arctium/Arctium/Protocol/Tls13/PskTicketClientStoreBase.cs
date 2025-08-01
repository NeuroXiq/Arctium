namespace Arctium.Protocol.Tls13
{
    public abstract class PskTicketClientStoreBase
    {
        public abstract void Save(PskTicket ticket);

        public abstract PskTicket[] GetToSendInClientHello();
    }
}
