﻿using Arctium.Standards.Connection.Tls.Tls12.Configuration.TlsExtensions;
using Arctium.Standards.Connection.Tls.Tls12.CryptoConfiguration;
using Arctium.Standards.Connection.Tls.Protocol.HandshakeProtocol;
using System.Security.Cryptography.X509Certificates;

namespace Arctium.Standards.Connection.Tls.Tls12.Configuration
{
    public class Tls12ServerConfig
    {
        public X509Certificate2[] Certificates;
        public CipherSuite[] EnableCipherSuites;
        public TlsHandshakeExtension[] HandshakeExtensions;

        //TODO tls12serverconfig
        public object clientVerification;
        public object SessionCache;
        public object enableRenegotiation;
        
        
    }
}
