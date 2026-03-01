using Arctium.Protocol.DNS.Model;
using System.Net;

namespace Arctium.Protocol.DNS
{
    public interface IDnsClientMessageIO
    {
        Task<Message> QueryServerAsync(DnsClientMessageIOArg arg);
    }
}
