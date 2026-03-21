namespace Arctium.Protocol.DNS.Server
{
    public interface IDnsServerNextDelegate
    {
        Task Next(DnsRequestContext context);
    }
}
