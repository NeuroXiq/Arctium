using Arctium.Shared.Other;
using Arctium.Standards.Connection.Tls.Tls13.API.Extensions;
using Arctium.Standards.Connection.Tls.Tls13.API.Messages;
using Arctium.Standards.Connection.Tls.Tls13.Model;
using Arctium.Standards.Connection.Tls.Tls13.Model.Extensions;
using System;
using System.Linq;

namespace Arctium.Standards.Connection.Tls.Tls13.API
{
    public class Tls13ClientConfig
    {
        internal Model.CipherSuite[] CipherSuites { get; private set; }
        internal Model.Extensions.SupportedGroupExtension.NamedGroup[] NamedGroups { get; private set; }
        internal Model.Extensions.SupportedGroupExtension.NamedGroup[] NamedGroupsToSendInKeyExchangeInClientHello1 { get; private set; }
        internal SignatureSchemeListExtension.SignatureScheme[] SignatureSchemes { get; private set; }
        internal Func<byte[][], ServerCertificateValidionResult> X509CertificateValidationCallback;
        internal ushort? ExtensionRecordSizeLimit { get; private set; }
        internal ExtensionClientALPNConfig ExtensionALPNConfig { get; private set; }
        internal ExtensionClientConfigServerName ExtensionClientConfigServerName { get; private set; }
        internal ExtensionClientConfigSignatureAlgorithmsCert ExtensionSignatureAlgorithmsCert { get; private set; }
        internal ClientConfigHandshakeClientAuthentication HandshakeClientAuthentication { get; private set; }
        internal ClientConfigPostHandshakeClientAuthentication PostHandshakeClientAuthentication { get; private set; }
        internal ExtensionClientConfigCertificateAuthorities ExtensionCertificateAuthorities { get; private set; }

        static readonly API.NamedGroup[] DefaultNamedGroups = Enum.GetValues<API.NamedGroup>();
        static readonly API.SignatureScheme[] DefaultSignatureSchemes = Enum.GetValues<API.SignatureScheme>();
        static readonly API.CipherSuite[] DefaultCipherSuites = Enum.GetValues<API.CipherSuite>();
        static readonly API.NamedGroup[] DefaultNamedGroupsToSendInClientHello1 = new API.NamedGroup[] { API.NamedGroup.X25519 };
        static readonly ushort? Extension_DefaultRecordSizeLimit = null;
        static readonly ExtensionClientALPNConfig DefaultExtensionALPNConfig = null;
        static readonly ExtensionClientConfigServerName DefaultExtensionClientConfigServerName = null;
        static readonly ExtensionClientConfigSignatureAlgorithmsCert DefaultExtensionSignatureAlgorithmsCert = null;
        static readonly ClientConfigHandshakeClientAuthentication DefaultHandshakeClientAuthentication = null;
        static readonly ClientConfigPostHandshakeClientAuthentication DefaultPostHandshakeClientAuthentication = null;
        static readonly ExtensionClientConfigCertificateAuthorities DefaultExtensionCertificateAuthorities = null;

        /// <summary>
        /// invokes <see cref="DefaultUnsafe"/> and sets validation callback
        /// default unsafe does not set validation callback (here this parameteris required).
        /// </summary>
        /// <param name="x509CertificateValidationCallback">validate certificate received from server</param>
        public static Tls13ClientConfig DefaultSafe(Func<byte[][], ServerCertificateValidionResult> x509CertificateValidationCallback)
        {
            var config = DefaultUnsafe();
            config.X509CertificateValidationCallback = x509CertificateValidationCallback;

            return config;
        }

        public static Tls13ClientConfig DefaultUnsafe()
        {
            var config = new Tls13ClientConfig();

            config.ConfigueCipherSuites(DefaultCipherSuites);
            config.ConfigueSupportedGroups(DefaultNamedGroups);
            config.ConfigueClientKeyShare(DefaultNamedGroupsToSendInClientHello1);
            config.ConfigueSupportedSignatureSchemes(DefaultSignatureSchemes);
            config.ConfigueExtensionRecordSizeLimit(Extension_DefaultRecordSizeLimit);
            config.ConfigureExtensionALPN(DefaultExtensionALPNConfig);
            config.ConfigureExtensionServerName(DefaultExtensionClientConfigServerName);
            config.ConfigureExtensionSignatureAlgorithmsCert(DefaultExtensionSignatureAlgorithmsCert);
            config.ConfigureHandshakeClientAuthentication(DefaultHandshakeClientAuthentication);
            config.ConfigurePostHandshakeClientAuthentication(DefaultPostHandshakeClientAuthentication);
            config.ConfigureExtensionCertificateAuthorities(DefaultExtensionCertificateAuthorities);

            return config;
        }

        /// <summary>
        /// Configure 'Certificate Authorities' extension (RFC 8446)
        /// If config is not null then client will send this extension in client hello.
        /// If config is null then client will not send this extension in client hello
        /// </summary>
        /// <param name="config">Configuration object that configures extension</param>
        public void ConfigureExtensionCertificateAuthorities(ExtensionClientConfigCertificateAuthorities config)
        {
            ExtensionCertificateAuthorities = config;
        }

        /// <summary>
        /// Configures post handshake client authentication.
        /// If configuration object is not null client will send 'post_handshake_auth' extension in client hello
        /// allowing server to perform post handshake client authentication
        /// If config object is null then client will not sent 'post_handhskake_auth' extension in client hello
        /// and post handshake authentication attempt from server will cause exception
        /// </summary>
        /// <param name="config">Confiuration object to configure post handshake auth or null disable support</param>
        public void ConfigurePostHandshakeClientAuthentication(ClientConfigPostHandshakeClientAuthentication config)
        {
            PostHandshakeClientAuthentication = config;
        }

        /// <summary>
        /// Configures client authentication that are performed during handskake (when server sends CertificateRequest during handskake)
        /// If config is not null then client behaviour is determined by configuration object.
        /// If value is null then client will not authenticate in handshake, if server require authentication empty certificate will be sent
        /// </summary>
        /// <param name="config">Configuration object or null if no authentication supported</param>
        public void ConfigureHandshakeClientAuthentication(ClientConfigHandshakeClientAuthentication config)
        {
            HandshakeClientAuthentication = config;
        }

        /// <summary>
        /// Configures Signatuer algorithms cert extension on client side.
        /// If value is not null, client will sent extension 'signature_schemes_cert' in client hello with values configured in object provided.
        /// If value is null then client will not sent exension 'signature_schemes_cert'
        /// </summary>
        /// <param name="config"></param>
        public void ConfigureExtensionSignatureAlgorithmsCert(ExtensionClientConfigSignatureAlgorithmsCert config)
        {
            ExtensionSignatureAlgorithmsCert = config;
        }

        /// <summary>
        /// Configures RFC 6066 Extension Server name on client side. If value is null then
        /// extension is not send. If value is not null then extension is send with parameters
        /// in object isntace
        /// </summary>
        /// <param name="defaultExtensionClientConfigServerName">configuration object or null if no extension should be send</param>
        public void ConfigureExtensionServerName(ExtensionClientConfigServerName config)
        {
            if (config != null)
                Validation.NotEmpty(config.HostName, nameof(config), "list of host names is empty. Provide at least one host name");

            ExtensionClientConfigServerName = config;
        }


        /// <summary>
        /// Configures application layer protocol negotiation extension for client.
        /// Protocol names specified in object will be send to server in ALPN client hello extension.
        /// alpnConfig can be null then extension will not be send to server
        /// </summary>
        public void ConfigureExtensionALPN(ExtensionClientALPNConfig alpnConfig)
        {
            if (alpnConfig != null)
                Validation.NotEmpty(alpnConfig.ProtocolList, nameof(alpnConfig), "protocol list must not be null and have at least one protocol to send to server");

            ExtensionALPNConfig = alpnConfig;
        }

        /// <summary>
        /// Configures record size limit extension. If parameter is null then no extension is send to server.
        /// If parameter is not null then extension is send. If RecordSizeLimit extension is received
        /// from serever then record layer is updated accordingly to negotiated record size plaintext length.
        /// If server do not respond to this extension then nothing happends and client continue
        /// without restricting record layer plaintext bytes
        /// </summary>
        /// <param name="recordSizeLimit">maximum length of plaintext bytes for record (after decryption). Null if do not send any extension</param>
        public void ConfigueExtensionRecordSizeLimit(int? recordSizeLimit)
        {
            if (recordSizeLimit.HasValue)
                Validation.NumberInRange(
                    recordSizeLimit.Value,
                    Tls13Const.Extension_RecordSizeLimit_RecordSizeLimit_MinValue,
                    Tls13Const.Extension_RecordSizeLimit_RecordSizeLimit_MaxValue,
                    nameof(recordSizeLimit));

            ExtensionRecordSizeLimit = (ushort?)recordSizeLimit;
        }

        public void ConfigueCipherSuites(API.CipherSuite[] suites)
        {
            Validation.NotEmpty(suites, nameof(suites));
            Validation.EnumValueDefined(suites, nameof(suites));

            CipherSuites = suites.Select(s => (Model.CipherSuite)s).ToArray();
        }

        /// <summary>
        /// Configures 'KeyShareClientHello' message
        /// </summary>
        /// <param name="groups">all allowed groups that can be used in key exchange</param>
        public void ConfigueSupportedGroups(NamedGroup[] allAllowedGroupsToUse)
        {

            Validation.NotEmpty(allAllowedGroupsToUse, nameof(allAllowedGroupsToUse));

            if (allAllowedGroupsToUse.Distinct().Count() != allAllowedGroupsToUse.Length)
                Validation.Argument(true, nameof(allAllowedGroupsToUse), "values must be unique");
            

            NamedGroups = allAllowedGroupsToUse.Select(g => (SupportedGroupExtension.NamedGroup)g).ToArray();
        }

        /// <param name="groupsToGenerateKeyInClientHello1">groups to generate key to send in client (KeyShareEntry.key_exchange value in tls 13 spec). this value 
        /// can be null or empty, then always server will perform retry request because after selecting 
        /// one of the offered group (specified by 'allAllowedGroupsToUse' parameter). 
        /// groups defined by this param will generate private-public key pair (computational expensive) so 
        /// should not define large amout of groups but send only few or only one e.g. X25519
        /// </param>
        public void ConfigueClientKeyShare(NamedGroup[] groupsToGenerateKeyInClientHello1)
        {
            groupsToGenerateKeyInClientHello1 = groupsToGenerateKeyInClientHello1 ?? new API.NamedGroup[0];

            if (groupsToGenerateKeyInClientHello1.Distinct().Count() != groupsToGenerateKeyInClientHello1.Length)
                Validation.Argument(true, nameof(groupsToGenerateKeyInClientHello1), "values must be unique");

            NamedGroupsToSendInKeyExchangeInClientHello1 = groupsToGenerateKeyInClientHello1.Select(g => (SupportedGroupExtension.NamedGroup)g).ToArray();
        }

        public void ConfigueSupportedSignatureSchemes(SignatureScheme[] schemes)
        {
            Validation.NotEmpty(schemes, nameof(schemes));
            Validation.EnumValueDefined(schemes, nameof(schemes));

            var internalList = schemes.Select(apiScheme => (SignatureSchemeListExtension.SignatureScheme)apiScheme).ToArray();

            SignatureSchemes = internalList;
        }

        public void ThrowIfInvalidState()
        {
            Validation.NotEmpty(CipherSuites, nameof(CipherSuites));
            Validation.NotEmpty(NamedGroups, nameof(NamedGroups));
            Validation.NotEmpty(SignatureSchemes, nameof(SignatureSchemes));

            var invalidGroups = NamedGroupsToSendInKeyExchangeInClientHello1
                .Where(willSendGroup => NamedGroups.All(allowedGroup => allowedGroup != willSendGroup))
                .ToArray();
            
            if (invalidGroups.Count() > 0)
            {
                string msg = "Invalid NamedGroupsToSendInClientHello1 configuration. One or more groups " +
                    $"doesnt match with allowed groups. All groups specified in {nameof(ConfigueClientKeyShare)} as groups to generate key " +
                    $"must also be specified as allowed group but they are not. Invalid values (not specified as allowed): " + 
                    $"{string.Join(",", invalidGroups.Select(x => x.ToString()))}. " + 
                    $"Make sure that all groups configured by a method: '{ConfigueClientKeyShare}' are also setup in method '{ConfigueSupportedGroups}' ";

                Validation.Argument(true, nameof(ConfigueSupportedGroups), msg);
            }
        }
    }
}
