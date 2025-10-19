using Arctium.Protocol.DNS.Model;

namespace Arctium.Protocol.DNS
{
    public interface IDnsServerRecursionService
    {
        Task<ResourceRecord[]> ResolveAsync(Message message);
    }
}
