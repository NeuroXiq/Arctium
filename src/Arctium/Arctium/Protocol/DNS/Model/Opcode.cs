using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNS.Model
{
    public enum Opcode : byte
    {
        Query = 0,
        IQuery = 1,
        Status = 2,

        // other are reserved
    }
}
