namespace Arctium.Standards.Connection.Tls.Protocol
{
    public static class ProtocolFormatConst
    {
        //
        // Record format consts
        //

        //public static class Record
        //{
        //    public const int MaxTlsPlainTextFragmentLength = 2 << 14;
        //    public const int MaxTlsCompressedFragmentLength = 2 << 14 + 1024;
        //    public const int MaxTlsCipherTextFragmentLength = 2 << 14 + 2048;
        //}

        ///<summary>Record header length in bytes</summary>
        public const int RecordHeaderLength = 5;
        public const int RecordContentTypeOffset = 0;
        public const int RecordProtocolVersionOffset = 1;
        public const int RecordLengthOffset = 3;
        public const int RecordFragmentOffset = 5;
        public const int MaxRecordLength = (2 << 14) + 2048;

        //
        // Handshake format consts
        //

        public const int HandshakeMaxLength = (2 << 24) - 1 + 4;
        public const int HandshakeHeaderLength = 4;
        ///<summary>Maximum length in bytes of handshake message (only 'content', 'header' is not included)</summary>
        public const int HandshakeMaxMessageLength = (2 << 24) - 1;
        public const int HandshakeLengthOffset = 1;
        public const int HandshakeTypeOffset = 0;


    }
}
