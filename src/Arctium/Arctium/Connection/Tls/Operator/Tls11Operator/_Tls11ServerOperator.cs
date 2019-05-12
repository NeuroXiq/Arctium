using System;
using Arctium.Connection.Tls.Protocol.AlertProtocol;
using Arctium.Connection.Tls.Protocol.ChangeCipherSpecProtocol;
using Arctium.Connection.Tls.ProtocolStream.HighLevelLayer;
using Arctium.Connection.Tls.ProtocolStream.RecordsLayer;
using Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer11;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using Arctium.Connection.Tls.Configuration;

namespace Arctium.Connection.Tls.Operator.Tls11Operator
{
    class _Tls11ServerOperator : TlsProtocolOperator
    {

        /*
         ClientHello                  -------->
                                                      ServerHello
                                                     Certificate*
                                               ServerKeyExchange*
                                              CertificateRequest*
                                   <--------      ServerHelloDone
      Certificate*
      ClientKeyExchange
      CertificateVerify*
      [ChangeCipherSpec]
      Finished                     -------->
                                               [ChangeCipherSpec]
                                   <--------             Finished
      Application Data             <------->     Application Data
             
             */

        HighLevelProtocolStream highLevelProtocolStream;
        Tls11HandshakeState handshakeState;
        Tls11ServerConfig config;


        private _Tls11ServerOperator(RecordLayer11 recordLayer, Tls11ServerConfig config)
        {
            highLevelProtocolStream = new HighLevelProtocolStream(recordLayer);
            handshakeState = new Tls11HandshakeState();
            handshakeState.Reset();
            this.config = config;
        }

        public static _Tls11ServerOperator Initialize(RecordIO recordIO, Tls11ServerConfig config)
        {
            recordIO.RecordVersion = new Protocol.ProtocolVersion(3, 2);
            RecordLayer11 rl = RecordLayer11.Initialize(recordIO);

            _Tls11ServerOperator server = new _Tls11ServerOperator(rl, config);

            return server;
        }

        public void OpenSession()
        {
            handshakeState.Reset();
            handshakeState.NextExpectedRead = HandshakeType.ClientHello;

            while (!handshakeState.HandshakeEnd)
            {
                highLevelProtocolStream.Read();
            }

            handshakeState.Reset();
        }

        private void ReceivedHandshakeMessageHandler(Handshake message, byte[] rawBytes)
        {
            if (handshakeState.NextExpectedRead == message.MsgType)
            {
                if (message.MsgType != HandshakeType.CertificateVerify && message.MsgType != HandshakeType.HelloRequest)
                {
                    handshakeState.PushRawBytes(rawBytes);
                }

                switch (message.MsgType)
                {
                    case HandshakeType.ClientHello:
                        OnClientHello(message as ClientHello);
                        break;
                    case HandshakeType.Certificate:
                        OnCertificate(message as Certificate);
                        break;
                    case HandshakeType.CertificateVerify:
                        OnCertifiateVerify(message as CertificateVerify);
                        break;
                    case HandshakeType.ClientKeyExchange:
                        OnClientKeyExchange(message as ClientKeyExchange);
                        break;
                    case HandshakeType.Finished:
                        OnFinished(message as Finished);
                        break;
                    default:
                        throw new NotImplementedException("Innternal error, exception for debug");
                }
            }
            else throw new TlsProtocolOperatorAlertException(AlertDescription.HandshakeFailure, "Received not expected handshake message");
        }

        private void OnFinished(Finished finished)
        {
            throw new NotImplementedException();
        }

        private void OnClientKeyExchange(ClientKeyExchange clientKeyExchange)
        {
            throw new NotImplementedException();
        }

        private void OnCertifiateVerify(CertificateVerify certificateVerify)
        {
            throw new NotImplementedException();
        }

        private void OnCertificate(Certificate certificate)
        {
            throw new NotImplementedException();
        }

        private void OnClientHello(ClientHello clientHello)
        {
            ServerHello serverHello = NegotiateServerHello(clientHello);

        }

        private ServerHello NegotiateServerHello(ClientHello clientHello)
        {
            throw new NotImplementedException();
        }

        private void HandshakeApplicationDataHandlerFataException(byte[] buffer, int offset, int length)
        {
            throw new TlsProtocolOperatorAlertException(AlertDescription.HandshakeFailure, "Received application data before end of handshake process");
        }

        private void HandshakeCCSHandlerFatalException(ChangeCipherSpec changeCipherSpec)
        {
            throw new TlsProtocolOperatorAlertException(AlertDescription.HandshakeFailure, "Received CCS before handshake process end");
        }

        private void HandshakeAlertHandlerFatalException(Alert alert)
        {
            throw new TlsProtocolOperatorAlertException(AlertDescription.HandshakeFailure, "Received alert during handshake : fatal error");
        }

        public override void WriteApplicationData(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }

        public override int ReadApplicationData(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }
    }
}
