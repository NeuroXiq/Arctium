using Arctium.Protocol.DNS.Model;

namespace Arctium.Protocol.DNS
{
    public interface IDnsClientMessageIOAdapter
    {
        Task<Message> QueryServerAsync(Message message);
    }
}
