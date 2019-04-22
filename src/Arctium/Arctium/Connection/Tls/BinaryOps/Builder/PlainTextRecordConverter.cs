using Arctium.Connection.Tls.RecordProtocol;
using System;

namespace Arctium.Connection.Tls.BinaryOps.Builder
{
    class PlainTextRecordConverter
    {
        public PlainTextRecordConverter() { }

        public TlsPlainText ConvertAsPlainText(Record plainTextRecord)
        {
            TlsPlainText plainText = new TlsPlainText();

            plainText.Fragment = plainTextRecord.Fragment;
            plainText.Length = plainTextRecord.Length;
            plainText.Type = plainTextRecord.Type;
            plainText.Version = plainTextRecord.Version;

            return plainText;
        }

        public TlsPlainText ConvertToPlainText(TlsGenericBlockCipherText genericBlockRecord)
        {
            TlsPlainText plainText = new TlsPlainText();

            plainText.Fragment = genericBlockRecord.Content;
            plainText.Length =   (ushort)genericBlockRecord.Content.Length;

            plainText.Type = genericBlockRecord.Type;
            plainText.Version = genericBlockRecord.Version;

            return plainText;
        }

        public TlsPlainText ConvertToPlainText(TlsGenericStreamCipherText genericStreamRecord)
        {
            throw new NotSupportedException();
        }
    }
}
