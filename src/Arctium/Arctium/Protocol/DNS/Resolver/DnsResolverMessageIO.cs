using Arctium.Protocol.DNS.Model;
using System.Net;

namespace Arctium.Protocol.DNS.Resolver
{
    public interface IDnsResolverMessageIO
    {
        Task<Message> QueryServerAsync(DnsResolverMessageIOArg arg);
    }
}
