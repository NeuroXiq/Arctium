using Arctium.Connection.Tls.Protocol;
using System.IO;
using System;
using Arctium.Connection.Tls.RecordProtocol;
using Arctium.Connection.Tls.HandshakeProtocol;

namespace Arctium.Connection.Tls.Operator
{
    class TlsProtocolOperator
    {
        RecordProtocolStream recordProtocolStream;
        ConnectionEnd entity;

        TlsProtocolOperator(RecordProtocolStream recordProtocolStream, ConnectionEnd entity)
        {
            this.recordProtocolStream = recordProtocolStream;
            this.entity = entity;
        }

        public static TlsProtocolOperator CreateServerSession(Stream innerStream)
        {
            SecurityParametersFactory secParamsFactory = new SecurityParametersFactory();
            SecurityParameters secParams = secParamsFactory.BuildInitialState(ConnectionEnd.Server);
            RecordProtocolStream recordStream = new RecordProtocolStream(innerStream, secParams);
            TlsProtocolOperator tlsOperator = new TlsProtocolOperator(recordStream, ConnectionEnd.Server);

            return tlsOperator;
        }

        public void Handshake()
        {
            if (entity == ConnectionEnd.Server)
            {
                HandshakeAsServer();
            }
            else throw new NotSupportedException();
        }

        private void HandshakeAsServer()
        {
            var r = recordProtocolStream.Read();

            string a = "asd";

            try
            {
                


            }
            catch (InvalidContentTypeException e)
            {

            }
            catch
            {
                throw;
            }
        }
    }
}
