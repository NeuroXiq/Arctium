using Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions;
using System;
using System.Security.Cryptography.X509Certificates;

namespace Arctium.Connection.Tls.Configuration.TlsExtensions
{
    public class SniExtension : TlsHandshakeExtension
    {
        public struct CertNamePair
        {
            public X509Certificate2 Certificate;
            public string ServerName;
        }

        //
        // fields used by server side
        //

        CertNamePair[] certNamePairs;

        public CertNamePair[] CertNamePairs
        {
            get
            {
                if (ConnectionEndType == ConnectionEnd.Client)
                    throw new InvalidOperationException("Cannot get CertNamePairs because SniExtension is created as client request");
                return certNamePairs;
            }
        }

        //
        // fields used by client side
        //

        string serverName;

        public string ServerName
        {
            get
            {
                if (ConnectionEndType == ConnectionEnd.Server)
                    throw new InvalidOperationException("Cannot get ServerName because SniExtenions is create as server response");
                return serverName;
            }
        }
        
        private SniExtension(string serverName) : base(HandshakeExtensionType.ServerName, ConnectionEnd.Client)
        {
            this.serverName = serverName;
        }

        private SniExtension(CertNamePair[] certNamePairs) : base(HandshakeExtensionType.ServerName, ConnectionEnd.Server)
        {
            this.certNamePairs = certNamePairs; 
        }

        public static SniExtension CreateAsClient(string serverNameToRequest)
        {
            return new SniExtension(serverNameToRequest);
        }

        public static SniExtension CreateAsServer(CertNamePair[] certNamePairs)
        {
            return new SniExtension(certNamePairs);
        }
    }
}
