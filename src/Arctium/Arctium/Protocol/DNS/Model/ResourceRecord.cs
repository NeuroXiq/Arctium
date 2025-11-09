using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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

        public T GetRData<T>() => (T)RData;

        public override string ToString()
        {
            return $"{Name} {Type} {Class} {RData}";
        }
    }
}
