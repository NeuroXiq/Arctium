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
        class FrameLen
        {
            public long Offset;
            public long Length;
        }

        QuickStreamState state;

        private List<FrameLen> readyFramentsToRead = new List<FrameLen>();

        public byte[] Data { get; private set; }
        public long Length { get; private set; }

        public long Cursor { get; private set; }
        public bool HasData { get { return GetFrameCursorPoints() != null; } }

        internal void RecvStreamFrame(CryptoFrame cf)
        {
            ExtendIfNeeded((long)cf.Offset + (long)cf.Data.Length);
            readyFramentsToRead.Add(new FrameLen() { Length = (long)cf.Length, Offset = (long)cf.Offset });
        }

        internal int Read(byte[] buffer, int offset, int length)
        {
            if (length > Length) throw new InvalidOperationException("internal - length > stream.Length (try read more than loaded)");
            if (length == 0 || !HasData) return 0;

            var toRead = GetFrameCursorPoints();
            var maxRead = length > toRead.Length ? toRead.Length : length;

            MemCpy.Copy(Data, toRead.Offset, buffer, offset, maxRead);

            toRead.Offset += maxRead;
            toRead.Length -= maxRead;

            if (toRead.Length == 0) readyFramentsToRead.Remove(toRead);

            return (int)maxRead;
        }

        FrameLen GetFrameCursorPoints()
        {
            return readyFramentsToRead.FirstOrDefault(n => n.Offset == Cursor);
        }

        void ExtendIfNeeded(long minSize)
        {
            if (minSize <= (long)Data.Length) return;

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
