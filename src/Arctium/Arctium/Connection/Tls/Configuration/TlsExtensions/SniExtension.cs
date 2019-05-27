﻿using Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions;
using System.Security.Cryptography.X509Certificates;
using System;
using Arctium.Connection.Tls.Exceptions;
using Arctium.Connection.Tls.Protocol.AlertProtocol;

namespace Arctium.Connection.Tls.Configuration.TlsExtensions
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

        CertNamePair[] certNamePairs;

        public string ServerName;
        
        public SniExtension(string serverName) : base(HandshakeExtensionType.ServerName)
        {
            ServerName = serverName;
        }

        public SniExtension(CertNamePair[] certNamePairs) : base(HandshakeExtensionType.ServerName)
        {
            this.certNamePairs = certNamePairs; 
        }

        internal override HandshakeExtension GetResponse(HandshakeExtension extensionFromClient)
        {
            ServerNameExtension clientSni = (ServerNameExtension)extensionFromClient;

            foreach (CertNamePair cnPair in certNamePairs)
            {
                if (cnPair.ServerName == clientSni.Name)
                    return new ServerNameExtension(null, NameType.HostName);
            }

            //not sure to throw this here

            throw new FatalAlertException(
                "SniExtension",
                "On building response for client server name request extension",
                (int)AlertDescription.UnrecognizedName,
                "client gives server name that do not match any server name on server side. This means that cannot select appriopriate certificate in response");

        }
    }
}
