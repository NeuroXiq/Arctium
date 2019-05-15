using Arctium.Connection.Tls.Operator.Tls11Operator;
using Arctium.Connection.Tls.ProtocolStream.RecordsLayer;
using System.IO;

namespace Arctium.Connection.Tls
{
    public class TlsClientConnection
    {
        public TlsClientConnection() { }


        public TlsStream Connect(Stream innerStream)
        {
            RecordIO recordIO = new RecordIO(innerStream);
            Tls11ClientOperator o = Tls11ClientOperator.Initialize(recordIO);
            o.OpenNewSession();

            return new TlsStream(o);
        }

        public int Read(byte[] buffer, int offset, int length)
        {
            return 0;
        }

        public void Write(byte[] buffer, int offset, int length)
        {

        }
    }
}
