using Arctium.Shared.Helpers.Buffers;
using Arctium.Standards.Connection.QUICv1Impl.Model;
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

        public byte[] Data { get; private set; }
        public ulong Length { get; private set; }

        internal void RecvStreamFrame(CryptoFrame cf)
        {
            ExtendIfNeeded(cf.Offset + (ulong)cf.Data.Length);
        }

        void ExtendIfNeeded(ulong minSize)
        {
            if (minSize <= (ulong)Data.Length) return;

            byte[] newBuf = new byte[minSize];
            checked
            {
                // todo should cast (int)?
                MemCpy.Copy(Data, 0, newBuf, 0, (int)Length);
            }

            Data = newBuf;
        }
    }
}
