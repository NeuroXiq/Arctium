using Arctium.Connection.Tls.Configuration;
using Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer12;
using System.IO;
using System;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;

namespace Arctium.Connection.Tls.Operator.Tls12Operator
{
    class Tls12ServerOperator : TlsProtocolOperator
    {
        Tls12ServerConfig config;
        RecordLayer12 recordLayer;

        Tls12ServerOperator(Tls12ServerConfig config, RecordLayer12 recordLayer)
        {
            this.config = config;
            this.recordLayer = recordLayer;
        }

        public static Tls12ServerOperator OpenNewSession(Tls12ServerConfig config, Stream innerStream)
        {
            //create initial state of the record layer
            //this initialization means that record layer algo is TLS_NULL_WITH_NULL_NULL
            //plain data exchange at this moment
            RecordLayer12 rl = RecordLayer12.Initialize(innerStream);
            
            //create operator object
            Tls12ServerOperator tlsOperator = new Tls12ServerOperator(config, rl);

            //first step, process handshake
            tlsOperator.OpenSession();

            //now, if no exception, state is after handshake
            //application data can be exchanged

            return tlsOperator;
        }

        public void OpenSession()
        {
            FragmentReader reader = new FragmentReader(recordLayer);
            HandshakeHandler handshakeFragmentsHandler = new HandshakeHandler(reader);



            Handshake msg = handshakeFragmentsHandler.Read();
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
