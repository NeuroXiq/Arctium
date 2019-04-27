namespace Arctium.Connection.Tls.Protocol.FormatConsts
{
    static class RecordConst
    {
        public const int MaxTlsRecordLength = (2 << 14) + 2048 + 5;
        public const int MaxTlsPlaintextFramentLength = 2 << 14;
        public const int MaxTlsCompressedFragmentLength = (2 << 14) + 1024;
        public const int MaxTlsCiphertextFragmentLength = (2 << 14) + 2048;

        public const int LengthOffset = 3;
        public const int HeaderLength = 5;
        
        

    }
}
