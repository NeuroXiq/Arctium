using Arctium.Connection.Tls.Tls13.API;
using Arctium.Connection.Tls.Tls13.Model;
using Arctium.Connection.Tls.Tls13.Model.Extensions;
using Arctium.Shared;
using Arctium.Shared.Helpers;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Shared.Security;
using Arctium.Standards;
using Arctium.Standards.PKCS1.v2_2;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Arctium.Connection.Tls.Tls13.Protocol
{
    class Tls13Protocol
    {
        private MessageReader handshakeReader;
        private Tls13ServerConfig serverConfig;
        private BufferForStream streamBuffer;
        private RecordLayer recordLayer;
        private Validate validate;
        private List<byte[]> handshakeContext = new List<byte[]>();
        private Crypto crypto;

        private ClientHello clientHello;

        public Tls13Protocol(Stream stream, Tls13ServerConfig serverConfig)
        {
            this.validate = new Validate();
            this.streamBuffer = new BufferForStream(stream);
            this.recordLayer = new RecordLayer(streamBuffer, validate);
            this.handshakeReader = new MessageReader(recordLayer, validate, handshakeContext);
            this.serverConfig = serverConfig;
        }

        public void OpenServer()
        {
            ClientHello hello = handshakeReader.LoadHandshakeMessage<ClientHello>(true);
            this.clientHello = hello;
            var clientKeyShare = hello.GetExtension<KeyShareClientHelloExtension>(ExtensionType.KeyShare)
                .ClientShares
                .Single(x => x.NamedGroup == SupportedGroupExtension.NamedGroup.X25519);

            byte[] privKey = new byte[32];
            GlobalConfig.RandomGeneratorCryptSecure(privKey, 0, 32);
            byte[] keyToSend = RFC7748.X25519_UCoord_9(privKey);

            byte[] sharedSecret = RFC7748.X25519(privKey, clientKeyShare.KeyExchangeRawBytes);
            var keyShare = new KeyShareServerHelloExtension(new KeyShareEntry(SupportedGroupExtension.NamedGroup.X25519, keyToSend));

            var encryptedExtensions = new EncryptedExtensions(new Extension[]
            {
                new ProtocolNameListExtension(new byte[][] {  Encoding.ASCII.GetBytes("http/1.1") })
            });

            // cert request
            var certificate = new Certificate(new byte[0],
                new CertificateEntry[]
                {
                    new CertificateEntry(CertificateType.X509, serverConfig.DerEncodedCertificateBytes, new Extension[0])
                });

            Extension[] extensions = new Extension[]
            {
                ServerSupportedVersionsExtension.ServerHelloTls13(),
                keyShare
            };

            this.crypto = new Crypto(CipherSuite.TLS_AES_128_GCM_SHA256, null, sharedSecret);

            ServerHello serverHello = new ServerHello(new byte[32], hello.LegacySessionId, CipherSuite.TLS_AES_128_GCM_SHA256, extensions);
            for (int i = 0; i < 32; i++) serverHello.Random[i] = (byte)i;
            
            ModelSerialization serializer = new ModelSerialization();
           
            serializer.ToBytes(serverHello);
            handshakeContext.Add(MemCpy.CopyToNewArray(serializer.SerializedData, 0, serializer.SerializedDataLength));
            recordLayer.Write(ContentType.Handshake, serializer.SerializedData, 0, serializer.SerializedDataLength);
            
            // var x = recordLayer.Read(true);

            serializer.Reset();

            var certVerify = new CertificateVerify(SignatureSchemeListExtension.SignatureScheme.RsaPssRsaeSha256, CertificateVerifySignature());

            serializer.ToBytes(encryptedExtensions);
            serializer.ToBytes(certificate);
            serializer.ToBytes(certVerify);

           

            crypto.InitEarlySecret(handshakeContext[0]);
            crypto.InitHandshakeSecret(handshakeContext);

            crypto.ChangeRecordLayerCrypto_Handshake(recordLayer, Endpoint.Server);

            recordLayer.Write(ContentType.Handshake, serializer.SerializedData, 0, serializer.SerializedDataLength);
            



            byte[] tosend = new byte[serializer.SerializedDataLength];
            MemCpy.Copy(serializer.SerializedData, 0, tosend, 0, serializer.SerializedDataLength);
            handshakeContext.Add(tosend);

            byte[] finishedVerData = crypto.ServerFinished(handshakeContext);
            var finished = new Finished(finishedVerData);

            serializer.ToBytes(finished);

            
            // send app data
        }

        byte[] CertificateVerifySignature()
        {
            var ext = this.clientHello.GetExtension<SignatureSchemeListExtension>(ExtensionType.SignatureAlgorithms);
            ext.Schemes.Single(s => s == SignatureSchemeListExtension.SignatureScheme.RsaPssRsaeSha256);


            string contextStr = "TLS 1.3, server CertificateVerify";
            byte[] stringBytes = Encoding.ASCII.GetBytes(contextStr);

            List<byte[]> tohash = new List<byte[]>();

            tohash.AddRange(this.handshakeContext);
            tohash.Add(this.serverConfig.DerEncodedCertificateBytes);

            byte[] hash = crypto.TranscriptHash(tohash.ToArray());

            byte[] tosign = new byte[64 + stringBytes.Length + 1 + hash.Length];

            int c = 0;

            MemOps.Memset(tosign, 0, 64, 0x20);
            c += 64;
            MemCpy.Copy(stringBytes, 0, tosign, c, stringBytes.Length);
            c += stringBytes.Length;
            tosign[c] = 0;
            c += 1;

            MemCpy.Copy(hash, 0, tosign, c, hash.Length);

            var key = new PKCS1v2_2API.PrivateKey(new PKCS1v2_2API.PrivateKeyCRT(serverConfig.CertificatePrivateKey));
            byte[] signature = PKCS1v2_2API.RSASSA_PSS_SIGN(key, tosign, hash.Length);

            return signature;
        }

        internal void Write(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }

        internal int Read(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }
    }
}
