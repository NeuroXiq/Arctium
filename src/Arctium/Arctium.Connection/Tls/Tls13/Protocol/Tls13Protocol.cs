using Arctium.Connection.Tls.Tls13.API;
using Arctium.Connection.Tls.Tls13.Model;
using Arctium.Connection.Tls.Tls13.Model.Extensions;
using Arctium.Shared.Helpers.Buffers;
using System;
using System.IO;

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

            var version = SupportedVersionsExtension.ServerHelloTls13();
            var keyShare = new KeyShareServerHelloExtension(null);
            var encryptedExtensions = new EncryptedExtensions(null);
            // cert request
            var certificate = new Certificate(null, null);
            var certVerify = new CertificateVerify(SignatureSchemeListExtension.SignatureScheme.EcdsaSecp256r1Sha256, null);
            var finished = new Finished(null);

            Extension[] extensions = new Extension[]
            {
                version
            };

            ServerHello serverHello = new ServerHello(new byte[32], hello.LegacySessionId, CipherSuite.TLS_AES_128_GCM_SHA256, extensions);
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
