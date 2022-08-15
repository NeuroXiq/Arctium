using Arctium.Connection.Tls.Tls13.API;
using Arctium.Connection.Tls.Tls13.Model;
using Arctium.Connection.Tls.Tls13.Model.Extensions;
using Arctium.Shared;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Shared.Security;
using Arctium.Standards;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Arctium.Connection.Tls.Tls13.Protocol
{
    class Tls13Protocol
    {
        private HandshakeReader handshakeReader;
        private Tls13ServerConfig serverConfig;
        private BufferForStream streamBuffer;
        private RecordLayer recordLayer;
        private Validate validate;

        public Tls13Protocol(Stream stream, Tls13ServerConfig serverConfig)
        {
            this.validate = new Validate();
            this.streamBuffer = new BufferForStream(stream);
            this.recordLayer = new RecordLayer(streamBuffer, validate);
            this.handshakeReader = new HandshakeReader(recordLayer, validate);
            this.serverConfig = serverConfig;
        }

        public void OpenServer()
        {
            ClientHello hello = handshakeReader.ReadClientHello();
            var clientKeyShare = hello.GetExtension<KeyShareClientHelloExtension>(ExtensionType.KeyShare)
                .ClientShares
                .Single(x => x.NamedGroup == SupportedGroupExtension.NamedGroup.X25519);


            byte[] privKey = new byte[32];
            byte[] keyToSend = RFC7748.X25519_UCoord_9(privKey);
            GlobalConfig.RandomGeneratorCryptSecure(privKey, 0, 32);

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

            var certVerify = new CertificateVerify(SignatureSchemeListExtension.SignatureScheme.EcdsaSecp256r1Sha256, null);
            var finished = new Finished(null);


            var version = SupportedVersionsExtension.ServerHelloTls13();
            var serverKeyShare = new KeyShareServerHelloExtension(new KeyShareEntry(SupportedGroupExtension.NamedGroup.X25519, new byte[0]));

            Extension[] extensions = new Extension[]
            {
                version,
                serverKeyShare
            };

            ServerHello serverHello = new ServerHello(new byte[32], hello.LegacySessionId, CipherSuite.TLS_AES_128_GCM_SHA256, extensions);

            ModelSerialization serializer = new ModelSerialization();

            serializer.ToBytes(serverHello);
            recordLayer.Write(ContentType.Handshake, serializer.Buffer.Buffer, 0, serializer.Buffer.DataLength);
            serializer.Reset();



            serializer.ToBytes(encryptedExtensions);
            serializer.ToBytes(certificate);
            serializer.ToBytes(certVerify);
            serializer.ToBytes(finished);

            recordLayer.Write(ContentType.Handshake, serializer.Buffer.Buffer, 0, serializer.Buffer.DataLength);
            // send app data
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
