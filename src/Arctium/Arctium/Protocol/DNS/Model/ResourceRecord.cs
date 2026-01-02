using Arctium.Protocol.DNS.Protocol;

namespace Arctium.Protocol.DNS.Model
{
    public class ResourceRecord
    {
        public string Name;
        public QType Type;
        public QClass Class;
        public uint TTL;
        public ushort RDLength;
        public object RData;

        public T AsRData<T>() => (T)RData;

        public override string ToString()
        {
            return $"{Name} {Type} {Class} {RData}";
        }

        public bool IsNameTypeClassEqual(string name, QClass qclass, QType qtype)
        {
            return DnsHelper.DnsNameEquals(Name, name)
                && Type == qtype
                && Class == qclass;
        }

        public bool IsNameTypeClassEqual(ResourceRecord other)
        {
            return IsNameTypeClassEqual(other.Name, other.Class, other.Type);
        }
    }
}
