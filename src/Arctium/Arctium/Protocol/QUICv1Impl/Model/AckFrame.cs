using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.QUICv1Impl.Model
{
    internal struct AckFrame
    {
        public FrameType Type;
        public ulong LargestAcknowledged;
        public ulong AckDelay;
        public ulong AckRangeCount;
        public ulong FirstAckRange;
        public Memory<AckRange> AckRange;
        public ECNCounts EcnCounts;
        public int A_TotalLength;
    }
}
