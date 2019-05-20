using Arctium.Connection.Tls.Configuration;
using Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer12;
using System.IO;
using System;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using System.Security.Cryptography.X509Certificates;
using Arctium.Connection.Tls.Protocol;
using Arctium.Connection.Tls.CryptoConfiguration;
using Arctium.Connection.Tls.CryptoFunctions;
using System.Security.Cryptography;

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

        //TODO this should be some 'context'
        OnHandshakeState handshakeState;
        OnCCSState ccsState;
        OnAppDataState appDataState;
        KeyExchangeService keyExchangeService;
        Tls12Secrets secrets;
        //TODO end 

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
            messagesContext = new HandshakeMessages12();
            handshakeState = new OnHandshakeState(recordLayer);
            ccsState = new OnCCSState(recordLayer);
            appDataState = new OnAppDataState(recordLayer);
            
            HelloExchangeService helloExchangeService = new HelloExchangeService(handshakeState, config.EnableCipherSuites);
            ClientAuthService clientAuthService = new ClientAuthService(handshakeState);


            //Client hello + server hello exchange
            helloExchangeService.ExchangeHelloAsServer(messagesContext);

            //send mandatory certificates (this implementation never assume that cert is not present)
            Certificate certificate = new Certificate(config.Certificates);
            handshakeState.Write(certificate);

            //key exchange service
            CryptoSuite suite = CryptoSuites.Get(messagesContext.ServerHello.CipherSuite);
            keyExchangeService = new KeyExchangeService(suite.KeyExchangeAlgorithm, suite.SigningAlgorithm, config.Certificates[0], handshakeState);

            //this is a conditional send based on parameters given in ctor above
            keyExchangeService.SendServerKeyExchange(messagesContext);

            //client authentication
            //do nothing but is present for future update how should it work
            clientAuthService.SendCertificateRequest( messagesContext);

            //done
            handshakeState.Write(new ServerHelloDone());

            //conditional certifiacate receive.
            clientAuthService.ReceiveCertificate(messagesContext);

            //mandatory step
            keyExchangeService.ReceiveClientKeyExchange(messagesContext);

            //conditional receive (currently do nothing)
            clientAuthService.ReceiveCertificateVerify(messagesContext);

            ProcessFinished();


            handshakeState.Read();

            string a = "";
        }

        private void ProcessFinished()
        {
            UpdateSecrets();
            RecordLayer12Params readParams, writeParams;

            GetSecParams(out writeParams, out readParams);

            // write mandatory Change cipher space (ignore result, is only 1 possible)
            ccsState.Read();
            //change write state of record layer 
            recordLayer.ChangeReadCipherSpec(readParams);

            ReadAndValidateFinished();

            
            ccsState.Write();
            //change read state in record layer
            recordLayer.ChangeWriteCipherSpec(writeParams);

            SendFinished();
        }

        private void GetSecParams(out RecordLayer12Params writeParams, out RecordLayer12Params readParams)
        {
            readParams =  new RecordLayer12Params();
            writeParams = new RecordLayer12Params();
            RecordCryptoType commonCryptoType = CryptoSuites.Get(messagesContext.ServerHello.CipherSuite).RecordCryptoType;

            readParams.BulkKey = secrets.ClientWriteKey;
            readParams.MacKey = secrets.ClientWriteMacKey;
            readParams.RecordCryptoType = commonCryptoType;

            writeParams.BulkKey = secrets.ServerWriteKey;
            writeParams.MacKey = secrets.ServerWriteMacKey;
            writeParams.RecordCryptoType = commonCryptoType;
        }

        private void UpdateSecrets()
        {
            byte[] premaster = keyExchangeService.GetPremasterAsServer(messagesContext);
            byte[] clientRandom = messagesContext.ClientHello.Random;
            byte[] serverRandom = messagesContext.ServerHello.Random;
            RecordCryptoType recordCryptoType = CryptoSuites.Get(messagesContext.ServerHello.CipherSuite).RecordCryptoType;

            secrets = SecretGenerator.GenerateTls12Secrets(recordCryptoType, premaster, clientRandom, serverRandom);
        }

        private void ReadAndValidateFinished()
        {
            

            OnHandshakeState.MsgData[] allMsg = handshakeState.ExchangeStack;

            SHA256 sha256c = SHA256.Create();

            for (int i = 0; i < allMsg.Length - 1; i++)
            {
                if (allMsg[i].Type == HandshakeType.HelloRequest || allMsg[i].Type == HandshakeType.CertificateVerify) continue;

                sha256c.TransformBlock(allMsg[i].RawBytes, 0, allMsg[i].RawBytes.Length, null, 0);
            }

            sha256c.TransformFinalBlock(allMsg[allMsg.Length - 1].RawBytes, 0, allMsg[allMsg.Length - 1].RawBytes.Length);

            Finished finished = (Finished)handshakeState.Read();

            byte[] hashSeed = sha256c.Hash;
            byte[] verifyData = PRF.Prf12(secrets.MasterSecret, "client finished", hashSeed, 12);

            for (int i = 0; i < verifyData.Length; i++)
            {
                if (verifyData[i] != finished.VerifyData[i]) throw new Exception("inalid finished");
            }


        }

     

        private void SendFinished()
        {
            OnHandshakeState.MsgData[] allMsg = handshakeState.ExchangeStack;

            SHA256 sha256c = SHA256.Create();

            for (int i = 0; i < allMsg.Length - 1; i++)
            {
                if (allMsg[i].Type == HandshakeType.HelloRequest || allMsg[i].Type == HandshakeType.CertificateVerify) continue;

                sha256c.TransformBlock(allMsg[i].RawBytes, 0, allMsg[i].RawBytes.Length, null, 0);
            }

            sha256c.TransformFinalBlock(allMsg[allMsg.Length - 1].RawBytes, 0, allMsg[allMsg.Length - 1].RawBytes.Length);

            byte[] hashSeed = sha256c.Hash;
            byte[] verifyData = PRF.Prf12(secrets.MasterSecret, "server finished", hashSeed, 12);


            
            Finished finished = new Finished(verifyData);

            handshakeState.Write(finished);
        }
    }
}
