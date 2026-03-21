namespace Arctium.Protocol.DNS.Server
{
    public class DnsServerNextDelegate : IDnsServerNextDelegate
    {
        private Func<DnsRequestContext, Task> next;

        public DnsServerNextDelegate(Func<DnsRequestContext, Task> next)
        {
            this.next = next;
        }

        public Task Next(DnsRequestContext context)
        {
            return next(context);
        }
    }
}
