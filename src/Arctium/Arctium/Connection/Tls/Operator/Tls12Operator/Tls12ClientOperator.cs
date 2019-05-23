using Arctium.Connection.Tls.Configuration;
using Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer12;
using System;
using System.IO;

namespace Arctium.Connection.Tls.Operator.Tls12Operator
{
    class Tls12ClientOperator : TlsProtocolOperator
    {
        RecordLayer12 recordLayer;
        Tls12ClientConfig config;

        public Tls12ClientOperator(Tls12ClientConfig config, Stream innerStream)
        {
            this.config = config;
            recordLayer = RecordLayer12.Initialize(innerStream);
        }

        public override void CloseNotify()
        {
            throw new NotImplementedException();
        }

        public override int ReadApplicationData(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }

        public override void WriteApplicationData(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }
    }
}
