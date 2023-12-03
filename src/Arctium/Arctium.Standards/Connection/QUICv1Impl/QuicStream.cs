using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Standards.Connection.QUICv1Impl
{
    public enum QuickStreamState
    {
        Ready,
        Send,
        DataSent,
        ResetSent,
        DataRecvd,
        ResetRecvd,

        // initial state of receiving party
        Recv,
        SizeKnown,
        DataRead
    }

    internal class QuicStream
    {
        QuickStreamState state;

        void RecvFrame()
        {

        }
    }
}
