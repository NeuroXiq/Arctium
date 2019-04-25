using Arctium.Connection.Tls.Protocol;
using Arctium.Connection.Tls.Protocol.RecordProtocol;

namespace Arctium.Connection.Tls.RecordTransform
{
    abstract class RecordCrypto
    {
        protected SecurityParameters currentSecParams;

        public RecordCrypto(SecurityParameters secParams)
        {
            currentSecParams = secParams;
        }

        public abstract Record Decrypt(Record record);
        public abstract Record Encrypt(Record record);

    }
}
