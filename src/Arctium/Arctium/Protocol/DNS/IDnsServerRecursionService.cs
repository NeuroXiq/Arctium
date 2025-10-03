using Arctium.Protocol.DNSImpl.Model;

namespace Arctium.Protocol.DNS
{
    public interface IDnsServerRecursionService
    {
        Task<ResourceRecord[]> ResolveAsync(Message message);
    }
}
