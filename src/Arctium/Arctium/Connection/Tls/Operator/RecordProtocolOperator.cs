using Arctium.Connection.Tls.Protocol;
using Arctium.Connection.Tls.RecordProtocol;
using System;
using System.IO;

namespace Arctium.Connection.Tls.Operator
{
    class RecordProtocolOperator
    {
        SecurityParameters currentSecurityParams;
        Stream innerStream;

        private RecordProtocolOperator(Stream innerStream)
        {

        }

        public RecordProtocolOperator CreateNew(Stream innerStream, ConnectionEnd entity)
        {
            SecurityParametersFactory securityParamsFactory = new SecurityParametersFactory();
            currentSecurityParams = securityParamsFactory.BuildInitialState(entity);

            this.innerStream = innerStream;

            return new RecordProtocolOperator(innerStream);
        }

        public void ChangeCipherSpec(SecurityParameters newParameters)
        {

        }

        public void Write()
        {

        }

        public Record Read() { throw new Exception(); }
    }
}
