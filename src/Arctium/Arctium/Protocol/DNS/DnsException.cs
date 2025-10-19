using Arctium.Protocol.DNS.Protocol;
using Arctium.Shared.Exceptions;

namespace Arctium.Protocol.DNS
{
    public class DnsException : ArctiumException
    {
        public DnsProtocolError ProtocolError { get; set; }

        // public DnsException(string msg) : base(msg) { }
        public DnsException(DnsProtocolError code) : this(code, null) { }
        public DnsException(DnsProtocolError code, string msg) : base($"Protocol error: {code.ToString()} ({(int)code}). Details: {msg}")
        {
            ProtocolError = code;
        }
    }
}
