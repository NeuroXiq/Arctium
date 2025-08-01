using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.QUICv1Impl.Model
{
    internal struct AckRange
    {
        public ulong Gap;
        public ulong ACKRangeLength;
    }
}
