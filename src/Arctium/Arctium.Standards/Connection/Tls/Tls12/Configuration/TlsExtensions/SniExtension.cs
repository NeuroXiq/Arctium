﻿using Arctium.Standards.Connection.Tls.Protocol.HandshakeProtocol.Extensions;
using System.Security.Cryptography.X509Certificates;
using System;
using Arctium.Standards.Connection.Tls.Exceptions;
using Arctium.Standards.Connection.Tls.Protocol.AlertProtocol;
using System.Collections.Generic;

namespace Arctium.Standards.Connection.Tls.Tls12.Configuration.TlsExtensions
{
    public class SniExtension : TlsHandshakeExtension
    {
        public struct CertNamePair
        {
            public X509Certificate2 Certificate;
            public string ServerName;

            public CertNamePair(X509Certificate2 cert, string name)
            {
                Certificate = cert;
                ServerName = name;
            }
        }

        public CertNamePair[] CertNamePairs;

        public string ServerName;

        public SniExtension(string serverName) : base(HandshakeExtensionType.ServerName)
        {
            ServerName = serverName;
        }

        public SniExtension(CertNamePair[] certNamePairs) : base(HandshakeExtensionType.ServerName)
        {
            this.CertNamePairs = certNamePairs; 
        }

        
    }
}
