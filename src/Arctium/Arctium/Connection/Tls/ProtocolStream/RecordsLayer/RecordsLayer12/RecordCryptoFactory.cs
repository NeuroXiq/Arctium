using Arctium.Connection.Tls.CryptoConfiguration;
using System;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer12
{
    class RecordCryptoFactory
    {
        public static readonly SecParams12 InitReadSecParams = new SecParams12() { };
        public static readonly SecParams12 InitWriteSecParams = new SecParams12() { };


        public static RecordCrypto CreateRecordCrypto(SecParams12 secParams)
        {
            throw new NotImplementedException();
        }
    }
}
