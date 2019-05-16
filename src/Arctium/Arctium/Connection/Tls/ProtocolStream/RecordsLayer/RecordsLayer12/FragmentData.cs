using Arctium.Connection.Tls.Protocol.RecordProtocol;
using System;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer12
{
    ///<summary>Encapsulates inner buffer and provides only copy capability from inner buffer.</summary>
    class FragmentData
    {
        public int Length { get; private set; }

        private byte[] fragmentBuffer;
        private int fragmentOffset;
        private int fragmentLength;

        public FragmentData(byte[] sourceBuff, int offset, int length)
        {
            fragmentBuffer = sourceBuff;
            fragmentOffset = offset;
            fragmentLength = length;
        }

        ///<summary>Copy all fragment bytes of <see cref="Length"/>
        ///length to the <paramref name="buffer"/> at <paramref name="offset"/> offset</summary>
        public void Copy(byte[] buffer, int offset)
        {
            Buffer.BlockCopy(fragmentBuffer, fragmentOffset, buffer, offset, fragmentLength);
        }
    }
}
