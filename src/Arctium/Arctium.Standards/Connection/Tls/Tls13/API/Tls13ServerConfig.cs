﻿using Arctium.Standards.Connection.Tls.Tls13.Model;
using Arctium.Standards.PKCS1.v2_2;
using static Arctium.Standards.Connection.Tls.Tls13.Model.Extensions.SupportedGroupExtension;

namespace Arctium.Standards.Connection.Tls.Tls13.API
{
    public class Tls13ServerConfig
    {
        public bool UseNewSessionTicketPsk { get; internal set; }
        internal CipherSuite[] CipherSuites;
        internal NamedGroup[] NamedGroups;

        public bool HandshakeRequestCertificateFromClient;
        public byte[] DerEncodedCertificateBytes;
        public RSAPrivateKey CertificatePrivateKey;
        public string RSAPrivateKeyString;

        public static Tls13ServerConfig DefaultUnsafe(byte[] certBytes, RSAPrivateKey privateKey)
        {
            var c = new Tls13ServerConfig();

            c.DerEncodedCertificateBytes = certBytes;
            c.CertificatePrivateKey = privateKey;

            c.UseNewSessionTicketPsk = true;
            c.HandshakeRequestCertificateFromClient = false;
            c.CipherSuites = new CipherSuite[]
                {
                    CipherSuite.TLS_AES_128_GCM_SHA256
                };

            c.NamedGroups = new NamedGroup[] { NamedGroup.X25519 };

            return c;
        }
    }
}
