namespace Arctium.Standards.ASN1.Serialization.X690.DER
{
    class BufferFrame
    {

        public byte[] Buffer { get; private set; }
        public long Offset { get; private set; }

        public CodingFrame CodingFrame { get; private set; }

        CodingFrameDecoder codingFrameDecoder;

        public BufferFrame(byte[] buffer)
        {
            Buffer = buffer;
            codingFrameDecoder = new CodingFrameDecoder();
        }

        public void SeekFromStart(long offset)
        {
            Offset = offset;
            //c
        }

        public void SeekFromCurrentPosition(long length)
        {
            Offset += length;
            //CodingFrame = codingFrameDecoder.DecodeFrame(Buffer, Offset);
        }

        public void SeekAfterFrame()
        {
            throw new System.Exception();
            //bufferFrame.SeekFromCurrentPosition(frameShift);
        }

        public void Update()
        {
            CodingFrame = codingFrameDecoder.DecodeFrame(Buffer, Offset);
        }
    }
}
