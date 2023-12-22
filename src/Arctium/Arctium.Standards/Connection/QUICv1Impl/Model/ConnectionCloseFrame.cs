using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Standards.Connection.QUICv1Impl.Model
{
    struct ConnectionCloseFrame
    {
        public FrameType Type;
        public ulong ErrorCode;
        public ulong FrameType;
        public ulong ReasonPhraseLength;
        public Memory<byte> ReasonPhrase;

        public int A_TotalLength;
        public QuicError A_ErrorCode => (QuicError)ErrorCode;

        public string GetReasonPhraseString()
        {
            if (ReasonPhraseLength > 0)
                return Encoding.UTF8.GetString(ReasonPhrase.Span);
            
            else return string.Empty;
        }
    }
}
