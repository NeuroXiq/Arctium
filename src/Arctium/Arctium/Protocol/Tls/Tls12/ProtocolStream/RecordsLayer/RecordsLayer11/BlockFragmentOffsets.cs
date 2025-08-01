namespace Arctium.Protocol.Tls.ProtocolStream.RecordsLayer.RecordsLayer11
{
    struct BlockFragmentOffsets
    {
        public int IVOffset;
        public int IVLength;
        public int ContentOffset;
        public int ContentLength;
        public int HmacOffset;
        public int HmacLength;
        public int PaddingOffset;
        public int PaddingLength;
    }
}
