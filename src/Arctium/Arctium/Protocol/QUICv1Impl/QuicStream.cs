using Arctium.Protocol.QUICv1;
using Arctium.Protocol.QUICv1Impl.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Arctium.Shared;

namespace Arctium.Protocol.QUICv1Impl
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
        // public long Length { get; private set; }

        public long Cursor { get; private set; }
        public bool HasData { get { return GetFrameCursorPoints() != null; } }

        public QuicStream()
        {
            Data = new byte[1024];
        }

        internal void RecvStreamFrame(CryptoFrame cf)
        {
            // todo this cannot work like this (very large buffers if ExtensIfNeede every time on append packet)
            // implement cyclic buffer?

            if ((ulong)Cursor > cf.Offset)
            {
               throw new QuicException("something wrong");
            }

            ExtendIfNeeded((long)cf.Offset + (long)cf.Data.Length);
            readyFramentsToRead.Add(new FrameLen() { Length = (long)cf.Length, Offset = (long)cf.Offset });
            MemCpy.Copy(cf.Data.Span, 0, Data, (int)cf.Offset, cf.Data.Length);
        }

        internal int Read(byte[] buffer, int offset, int length)
        {
            if (length == 0 || !HasData) return 0;

            var toRead = GetFrameCursorPoints();
            var maxRead = length > toRead.Length ? toRead.Length : length;

            MemCpy.Copy(Data, toRead.Offset, buffer, offset, maxRead);

            Cursor += maxRead;
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
                MemCpy.Copy(Data, 0, newBuf, 0, Data.Length);
            }

            Data = newBuf;
        }
    }
}
