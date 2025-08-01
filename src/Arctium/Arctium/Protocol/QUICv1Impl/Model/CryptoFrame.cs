using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.QUICv1Impl.Model
{
    internal struct CryptoFrame
    {
        public FrameType Type;
        public ulong Offset;
        public ulong Length;
        public Memory<byte> Data;

        public int A_TotalLength;
    }
}
