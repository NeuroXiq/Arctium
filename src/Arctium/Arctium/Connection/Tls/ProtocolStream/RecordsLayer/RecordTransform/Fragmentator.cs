using Arctium.Connection.Tls.Protocol.FormatConsts;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordTransform
{
    class Fragmentator
    {
        public Fragmentator() { }

        

        public int[] SplitToFragments(byte[] buffer, int offset, int count)
        {
            int maxFragmentLength = RecordConst.MaxTlsPlaintextFramentLength;

            int buffersCount = (count / maxFragmentLength) + 1;
            int[] lengths = new int[buffersCount];

            //max lengths
            for (int i = 0; i < buffersCount - 1; i++)
            {
                lengths[i] = maxFragmentLength;
            }

            //last length
            int lastLength = count % maxFragmentLength;
            if (lastLength == 0) lengths[buffersCount - 1] = maxFragmentLength;
            else lengths[buffersCount - 1] = lastLength;

            return lengths;

        }
    }
}
/*public byte[][] SplitToFragments(byte[] buffer, int offset, int count)
        {
            int div = RecordConst.MaxTlsPlaintextFramentLength;

            int buffersCount = (count / div) + 1;
            byte[][] splitted = new byte[buffersCount][];

            //max copy
            for (int i = 0; i < buffersCount - 1; i++)
            {
                int sourceCopyStart = offset + (i * div);

                splitted[i] = new byte[div];
                Array.Copy(buffer, sourceCopyStart, splitted[i], 0, div);
            }

            //last copy
            int lastBlockOffset = buffersCount * div;
            int lastBlockLength = count % div;
            Array.Copy(buffer, lastBlockOffset, splitted[buffersCount - 1], 0, lastBlockLength);

            return splitted; 
        }*/
