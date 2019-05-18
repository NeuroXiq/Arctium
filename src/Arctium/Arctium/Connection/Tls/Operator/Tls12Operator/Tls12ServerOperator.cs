using Arctium.Connection.Tls.Configuration;
using Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer12;
using System.IO;
using System;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using System.Security.Cryptography.X509Certificates;
using Arctium.Connection.Tls.Protocol;

namespace Arctium.Connection.Tls.Operator.Tls12Operator
{
    /*         
     All services (listed on right side) reads message if message is expect in current context


     ClientHello <--> ServerHello                               [HelloExchangeService]
     Certificate                                                [<NULL>, send certyificate always]
     ClientKeyExchange <--> ServerKeyExchange                   [KeyExchangeService]
     CertificateRequest <--> ( Certificate + CertificateVerify) [ClientAuthService]
     ServerHelloDone                                            [<NULL>, always send hellodone]
     
      
      
      [ChangeCipherSpec]
      Finished                     -------->
                                               [ChangeCipherSpec]
                                   <--------             Finished
      Application Data             <------->     Application Data
      */

    //COPY PASTE FROM RFC 5246, url: https://tools.ietf.org/html/rfc5246#section-7.3
    
    /*

     Client                                               Server

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


    class Tls12ServerOperator : TlsProtocolOperator
    {
        Tls12ServerConfig config;
        RecordLayer12 recordLayer;
        HandshakeMessages12 messagesContext;

        Tls12ServerOperator(Tls12ServerConfig config, Stream innerStream)
        {
            this.config = config;

            //create initial state of the record layer
            //this initialization means that record layer algo is TLS_NULL_WITH_NULL_NULL
            //plain data exchange at this moment

            this.recordLayer = RecordLayer12.Initialize(innerStream);
        }

        //
        // public methods
        //

        public override int ReadApplicationData(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }

        public override void WriteApplicationData(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }


        public static Tls12ServerOperator OpenNewSession(Tls12ServerConfig config, Stream innerStream)
        {
            //create operator object
            Tls12ServerOperator tlsOperator = new Tls12ServerOperator(config, innerStream);

            //first step, process handshake
            tlsOperator.OpenSession();

            //now, if no exception, state is after handshake
            //application data can be exchanged using WriteApplicationData/ReadApplicationData methods inherited by TlsProtocolOperator

            return tlsOperator;
        }

        public void OpenSession()
        {
            OnHandshakeState handshakeRW = new OnHandshakeState(recordLayer);
            OnCCSState ccsState = new OnCCSState(recordLayer);
            OnAppDataState appDataState = new OnAppDataState(recordLayer);

            messagesContext = new HandshakeMessages12();
            HelloExchangeService helloExchangeService = new HelloExchangeService(handshakeRW, config.EnableCipherSuites);
            ClientAuthService clientAuthService = new ClientAuthService(handshakeRW);



            //Client hello + server hello exchange
            helloExchangeService.ExchangeHelloAsServer(messagesContext);

            //send mandatory certificates (this implementation never assume that cert is not present)
            Certificate certificate = new Certificate(config.Certificates);
            handshakeRW.Write(certificate);

            //key exchange service
            CryptoSuite suite = CryptoSuites.Get(messagesContext.ServerHello.CipherSuite);
            KeyExchangeService keyExchangeService = new KeyExchangeService(suite.KeyExchangeAlgorithm, suite.SigningAlgorithm, handshakeRW);

            //this is a conditional send based on parameters given in ctor above
            keyExchangeService.SendServerKeyExchange(messagesContext);

            //client authentication
            //do nothing but is present for future update how should it work

            clientAuthService.SendCertificateRequest( messagesContext);

            //done
            handshakeRW.Write(new ServerHelloDone());

            //conditional certifiacate receive.
            clientAuthService.ReceiveCertificate(messagesContext);

            //mandatory step
            keyExchangeService.ReceiveClientKeyExchange(messagesContext);

            //conditional receive
            clientAuthService.ReceiveCertificateVerify(messagesContext);

          

            






            
        }
    }
}
