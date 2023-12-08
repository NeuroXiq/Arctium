using Arctium.Shared.Other;
using Arctium.Standards.Connection.Tls13.Extensions;
using Arctium.Standards.Connection.Tls13.Messages;
using Arctium.Standards.Connection.Tls13Impl.Model;
using Arctium.Standards.Connection.Tls13Impl.Model.Extensions;
using Arctium.Standards.Connection.Tls13Impl.Protocol;
using Arctium.Standards.PKCS1.v2_2;
using Arctium.Standards.X509.X509Cert;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Arctium.Standards.Connection.Tls13
{
    public class Tls13ServerConfig
    {
        internal Tls13Impl.Model.CipherSuite[] CipherSuites { get; private set; }
        internal ExtensionServerConfigSupportedGroups ExtensionSupportedGroups { get; private set; }
        internal SignatureSchemeListExtension.SignatureScheme[] SignatureSchemes { get; private set; }
        internal ushort? ExtensionRecordSizeLimit { get; private set; }
        internal ExtensionServerConfigALPN ExtensionALPN { get; private set; }
        internal ExtensionServerConfigServerName ExtensionServerName { get; private set; }
        internal ServerConfigHandshakeClientAuthentication HandshakeClientAuthentication { get; private set; }
        internal ExtensionServerConfigOidFilters ExtensionServerConfigOidFilters { get; private set; }
        internal ServerConfigPostHandshakeClientAuthentication PostHandshakeClientAuthentication { get; private set; }
        internal ExtensionServerConfigCertificateAuthorities ExtensionCertificateAuthorities { get; private set; }
        internal ServerConfigPreSharedKey PreSharedKey { get; private set; }
        internal ExtensionServerConfigGREASE GREASE { get; private set; }
        internal bool QuicIntegration { get; private set; }

        public X509CertWithKey[] CertificatesWithKeys { get; private set; }

        static readonly ushort? DefaultExtensionRecordSizeLimit = null;
        static readonly ExtensionServerConfigALPN DefaultExtensionALPN = null;
        static readonly ExtensionServerConfigServerName DefaultExtensionServerName = null;
        static readonly ServerConfigHandshakeClientAuthentication DefaultServerConfigHandshakeClientAuthentication;
        static readonly ExtensionServerConfigOidFilters DefaultExtensionServerConfigOidFilters = null;
        static readonly ServerConfigPostHandshakeClientAuthentication DefaultPostHandshakeClientAuthentication = null;
        static readonly ExtensionServerConfigCertificateAuthorities DefaultExtensionCertificateAuthorities = null;
        static readonly ExtensionServerConfigSupportedGroups DefaultExtensionSupportedGroups = new ExtensionServerConfigSupportedGroups(Enum.GetValues<NamedGroup>());
        static readonly ExtensionServerConfigGREASE DefaultGREASE = new ExtensionServerConfigGREASE();

        static SignatureScheme[] DefaultAllSignateSchemes = new SignatureScheme[]
            {
                SignatureScheme.EcdsaSecp256r1Sha256,
                SignatureScheme.EcdsaSecp384r1Sha384,
                SignatureScheme.EcdsaSecp521r1Sha512,
                SignatureScheme.RsaPssRsaeSha256,
                SignatureScheme.RsaPssRsaeSha384,
                SignatureScheme.RsaPssRsaeSha512,
            };

        static CipherSuite[] DefaultCipherSuites = new CipherSuite[]
        {
            CipherSuite.TLS_AES_128_GCM_SHA256,
            CipherSuite.TLS_AES_256_GCM_SHA384,
            CipherSuite.TLS_CHACHA20_POLY1305_SHA256
        };

        /// <summary>
        /// Creates default instance of server configuration
        /// </summary>
        /// <param name="listOfCertsWithKeys"></param>
        /// <returns></returns>
        public static Tls13ServerConfig Default(X509CertWithKey[] listOfCertsWithKeys)
        {
            var c = new Tls13ServerConfig();

            c.CertificatesWithKeys = listOfCertsWithKeys;

            c.ConfigueCipherSuites(DefaultCipherSuites);
            c.ConfigueExtensionSupportedGroups(DefaultExtensionSupportedGroups);
            c.ConfigueSupportedSignatureSchemes(DefaultAllSignateSchemes);
            c.ConfigureExtensionRecordSizeLimit(DefaultExtensionRecordSizeLimit);
            c.ConfigueExtensionALPN(DefaultExtensionALPN);
            c.ConfigureExtensionServerName(DefaultExtensionServerName);
            c.ConfigureHandshakeClientAuthentication(DefaultServerConfigHandshakeClientAuthentication);
            c.ConfigureExtensionOidFilters(DefaultExtensionServerConfigOidFilters);
            c.ConfigurePostHandshakeClientAuthentication(DefaultPostHandshakeClientAuthentication);
            c.ConfigureExtensionCertificateAuthorities(DefaultExtensionCertificateAuthorities);
            c.ConfigurePreSharedKey(DefaultPreSharedKey());
            c.ConfigureGREASE(DefaultGREASE);

            return c;
        }

        /// <summary>
        /// Configures GREASE (RFC 8701).
        /// If value is not null then server behaviour determined by config.
        /// If value is null then server will not send any GRASE value
        /// in any field in any message (disabled everywhere)
        /// </summary>
        public void ConfigureGREASE(ExtensionServerConfigGREASE config)
        {
            GREASE = config;
        }

        /// <summary>
        /// Configures pre shared key.
        /// If value is not null then server will use pre-shared keys from configuration
        /// If value is null then server will not use pre-shared keys and always perform
        /// full handshake
        /// </summary>
        /// <param name="serverConfigPreSharedKey"></param>
        public void ConfigurePreSharedKey(ServerConfigPreSharedKey config)
        {
            PreSharedKey = config;
        }

        private static ServerConfigPreSharedKey DefaultPreSharedKey()
        {
            return new ServerConfigPreSharedKey(new PskTicketServerStoreDefaultInMemory(), 1);
        }


        /// <summary>
        /// Configures 'Certificate Authorities' (RFC 8446) extension.
        /// If config is not null server will send this extension in CertificateRequest (in handshake and post-handshake client authentication)
        /// If config is null then server will not send this extension
        /// </summary>
        /// <param name="config">Configuration object or null is server should not send this extension</param>
        public void ConfigureExtensionCertificateAuthorities(ExtensionServerConfigCertificateAuthorities config)
        {
            ExtensionCertificateAuthorities = config;
        }

        /// <summary>
        /// Configures post handshake client authentication.
        /// If config is not null then server can at any time request authentication from client. Server will validate if client 
        /// is owner of private certificates that was sent.
        /// If config is null then post handshake client authentication is disabled.
        /// </summary>
        /// <param name="config">configuration of post handshake client authentication or null if disabled</param>
        public void ConfigurePostHandshakeClientAuthentication(ServerConfigPostHandshakeClientAuthentication config)
        {
            PostHandshakeClientAuthentication = config;
        }

        /// <summary>
        /// Configures 'Oid filters' extension (RFC 8446).
        /// If value is not null server will send OID filters to client in 'CertificateRequest' message
        /// If value is null server will not send this extension CertificateRequest message
        /// </summary>
        /// <param name="defaultExtensionServerConfigOidFilters"></param>
        public void ConfigureExtensionOidFilters(ExtensionServerConfigOidFilters config)
        {
            ExtensionServerConfigOidFilters = config;
        }


        /// <summary>
        /// Configures client authentication on handshake.
        /// If configuration is not nulll then server will require authentication from client (will send CertificateRequest message)
        /// If configuration is null then server will not sent CertificateRequest and process without client authentication
        /// </summary>
        /// <param name="config">configuration object or null</param>
        public void ConfigureHandshakeClientAuthentication(ServerConfigHandshakeClientAuthentication config)
        {
            HandshakeClientAuthentication = config;
        }

        /// <summary>
        /// Configures RFC 6066 extension server name. 
        /// When null server do nothing
        /// if not null then server will do action from configured object
        /// </summary>
        /// <param name="defaultExtensionServerName">config what to do with client server name extension or null if ignore it</param>
        public void ConfigureExtensionServerName(ExtensionServerConfigServerName config)
        {
            ExtensionServerName = config;
        }


        /// <summary>
        /// Configures Application Layer Protocol Negotiation extension (rfc7301)
        /// If input value is null server ignores ALPN extension from client and do not send response
        /// Is invoked only when client sends ALPN extension, if client did not sent ALPN extension
        /// then nothing happend and handshake continue, selector is never invoked
        /// </summary>
        /// <param name="protocolSelector">Selector function that will select protocol or do other action</param>
        public void ConfigueExtensionALPN(ExtensionServerConfigALPN config)
        {
            ExtensionALPN = config;
        }

        /// <summary>
        /// Configures Record Size Limit extension (RFC 8449).
        /// If value is not null and RecordSizeLImit extension received from client,
        /// then server will select minimum value (configured by 'sizeLimit' param and received from client)
        /// Then server will restrict record layer to send records of max plaintext length equal to value mentioned before.
        /// If sizeLimit set to null and client sends extension then limit will be equal to value from client extension.
        /// If client do not sent  extension then nothing happends and server continue
        /// </summary>
        /// <param name="sizeLimit">Maximum record size to negotiate, or null if no limit requred</param>
        public void ConfigureExtensionRecordSizeLimit(int? sizeLimit)
        {
            if (sizeLimit.HasValue)
            {
                Validation.NumberInRange(sizeLimit.Value,
                    Tls13Const.Extension_RecordSizeLimit_RecordSizeLimit_MinValue,
                    Tls13Const.Extension_RecordSizeLimit_RecordSizeLimit_MaxValue,
                    nameof(sizeLimit));
            }

            ExtensionRecordSizeLimit = (ushort?)sizeLimit;
        }

        /// <summary>
        /// Configures cipher suites that can be used by instance
        /// </summary>
        public void ConfigueCipherSuites(CipherSuite[] suites)
        {
            Validation.NotEmpty(suites, nameof(suites));
            Validation.EnumValueDefined(suites, nameof(suites));

            CipherSuites = suites.Select(s => (Tls13Impl.Model.CipherSuite)s).ToArray();
        }

        /// <summary>
        /// Configures NamedGroups that can be used by instance
        /// </summary>
        public void ConfigueExtensionSupportedGroups(ExtensionServerConfigSupportedGroups config)
        {
            Validation.NotNull(config, nameof(config));

            ExtensionSupportedGroups = config;
        }

        public void ThrowIfInvalidObjectState()
        {
            Validation.NotEmpty(SignatureSchemes, nameof(SignatureSchemes));
            Validation.NotNull(ExtensionSupportedGroups, nameof(ExtensionSupportedGroups));
            Validation.NotEmpty(CipherSuites, nameof(CipherSuites));
            Validation.NotEmpty(CertificatesWithKeys, nameof(CertificatesWithKeys), "Certificate list cannot be empty");

            var configuredSignatures = Crypto.SignaturesInfo.Where(info => SignatureSchemes.Contains(info.SignatureScheme));
            var certsForSignatures = CertificatesWithKeys.Where(cert =>
            {
                var certAlgo = cert.Certificate.SubjectPublicKeyInfo.AlgorithmIdentifier.Algorithm;
                var certSupportAlgo = configuredSignatures.Any(info => info.RelatedPublicKeyType == certAlgo);

                return certSupportAlgo;
            });

            // configures certificates and signatureschemes does not match
            if (!certsForSignatures.Any())
            {
                string msg = $"Current configurations of: X509Certificates and {nameof(SignatureScheme)} does not match. That means that " +
                    $"all certificates cannot generate signatures specified in {nameof(SignatureScheme)} list. Change X509Certificate list " +
                    $"or change {SignatureSchemes} to have valid signature-certificate configuration for at least single certificate";

                Validation.Argument(true, nameof(SignatureScheme), msg);
            }
        }

        public void ConfigueSupportedSignatureSchemes(SignatureScheme[] schemes)
        {
            Validation.NotEmpty(schemes, nameof(schemes));

            foreach (var value in schemes) Validation.EnumValueDefined(value, nameof(schemes));

            var internalList = schemes.Select(apiScheme => (SignatureSchemeListExtension.SignatureScheme)apiScheme).ToArray();

            SignatureSchemes = internalList;
        }

        internal void ConfigureQuicIntegration(bool isQuicIntegration)
        {
            throw new NotImplementedException();
        }
    }
}
