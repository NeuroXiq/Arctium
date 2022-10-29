﻿using Arctium.Shared.Other;
using Arctium.Standards.Connection.Tls.Tls13.API.Extensions;
using Arctium.Standards.Connection.Tls.Tls13.API.Messages;
using Arctium.Standards.Connection.Tls.Tls13.Model;
using Arctium.Standards.Connection.Tls.Tls13.Model.Extensions;
using Arctium.Standards.Connection.Tls.Tls13.Protocol;
using Arctium.Standards.PKCS1.v2_2;
using Arctium.Standards.X509.X509Cert;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Arctium.Standards.Connection.Tls.Tls13.API
{
    public class Tls13ServerConfig
    {
        public bool UseNewSessionTicketPsk { get; internal set; }
        internal Model.CipherSuite[] CipherSuites { get; private set; }
        internal SupportedGroupExtension.NamedGroup[] NamedGroups { get; private set; }
        internal SignatureSchemeListExtension.SignatureScheme[] SignatureSchemes { get; private set; }
        internal ushort? ExtensionRecordSizeLimit { get; private set; }
        internal Func<ExtensionServerALPN, ExtensionServerALPN.Result> ExtensionALPN { get; private set; }
        internal ExtensionServerConfigServerName ExtensionServerName { get; private set; }
        internal ServerConfigHandshakeClientAuthentication HandshakeClientAuthentication { get; private set; }
        internal ExtensionServerConfigOidFilters ExtensionServerConfigOidFilters { get; private set; }

        public X509CertWithKey[] CertificatesWithKeys { get; private set; }

        static readonly API.NamedGroup[] DefaultAllGroups = Enum.GetValues<API.NamedGroup>();
        static readonly ushort? DefaultExtensionRecordSizeLimit = null;
        static readonly Func<ExtensionServerALPN, ExtensionServerALPN.Result> DefaultExtensionALPN = null;
        static readonly ExtensionServerConfigServerName DefaultExtensionServerName = null;
        static readonly ServerConfigHandshakeClientAuthentication DefaultServerConfigHandshakeClientAuthentication;
        static readonly ExtensionServerConfigOidFilters DefaultExtensionServerConfigOidFilters = null;

        static API.SignatureScheme[] DefaultAllSignateSchemes = new SignatureScheme[]
            {
                SignatureScheme.EcdsaSecp256r1Sha256,
                SignatureScheme.EcdsaSecp384r1Sha384,
                SignatureScheme.EcdsaSecp521r1Sha512,
                SignatureScheme.RsaPssRsaeSha256,
                SignatureScheme.RsaPssRsaeSha384,
                SignatureScheme.RsaPssRsaeSha512,
            };

        static API.CipherSuite[] DefaultCipherSuites = new API.CipherSuite[]
        {
            API.CipherSuite.TLS_AES_128_GCM_SHA256,
            API.CipherSuite.TLS_AES_256_GCM_SHA384,
            API.CipherSuite.TLS_CHACHA20_POLY1305_SHA256
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
            c.UseNewSessionTicketPsk = true;

            c.ConfigueCipherSuites(DefaultCipherSuites);
            c.ConfigueSupportedNamedGroupsForKeyExchange(DefaultAllGroups);
            c.ConfigueSupportedSignatureSchemes(DefaultAllSignateSchemes);
            c.ConfigureExtensionRecordSizeLimit(DefaultExtensionRecordSizeLimit);
            c.ConfigueExtensionALPN(DefaultExtensionALPN);
            c.ConfigureExtensionServerName(DefaultExtensionServerName);
            c.ConfigureHandshakeClientAuthentication(DefaultServerConfigHandshakeClientAuthentication);
            c.ConfigureExtensionServerConfigOidFilters(DefaultExtensionServerConfigOidFilters);

            return c;
        }

        /// <summary>
        /// Configures 'Oid filters' extension (RFC 8446).
        /// If value is not null server will send OID filters to client in 'CertificateRequest' message
        /// If value is null server will not send this extension CertificateRequest message
        /// </summary>
        /// <param name="defaultExtensionServerConfigOidFilters"></param>
        public void ConfigureExtensionServerConfigOidFilters(ExtensionServerConfigOidFilters config)
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
            this.HandshakeClientAuthentication = config;
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
        public void ConfigueExtensionALPN(Func<ExtensionServerALPN, ExtensionServerALPN.Result> protocolSelector)
        {
            this.ExtensionALPN = protocolSelector;
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
        public void ConfigueCipherSuites(API.CipherSuite[] suites)
        {
            Validation.NotEmpty(suites, nameof(suites));
            Validation.EnumValueDefined(suites, nameof(suites));

            CipherSuites = suites.Select(s => (Model.CipherSuite)s).ToArray();
        }

        /// <summary>
        /// Configures NamedGroups that can be used by instance
        /// </summary>
        public void ConfigueSupportedNamedGroupsForKeyExchange(API.NamedGroup[] groups)
        {
            foreach (var v in groups) Validation.EnumValueDefined(v, nameof(groups));

            NamedGroups = groups.Select(apiGroup => (SupportedGroupExtension.NamedGroup)apiGroup).ToArray();
        }

        public void ThrowIfInvalidObjectState()
        {
            Validation.NotEmpty(SignatureSchemes, nameof(Tls13ServerConfig.SignatureSchemes));
            Validation.NotEmpty(NamedGroups, nameof(NamedGroups));
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
    }
}
