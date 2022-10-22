using Arctium.Shared.Other;
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
        internal Model.CipherSuite[] CipherSuites;
        internal SupportedGroupExtension.NamedGroup[] NamedGroups;
        internal SignatureSchemeListExtension.SignatureScheme[] SignatureSchemes;

        public bool HandshakeRequestCertificateFromClient;
        public X509CertWithKey[] CertificatesWithKeys { get; private set; }

        static API.NamedGroup[] DefaultAllGroups = Enum.GetValues<API.NamedGroup>();

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
            c.HandshakeRequestCertificateFromClient = false;


            c.ConfigueCipherSuites(DefaultCipherSuites);
            c.ConfigueSupportedNamedGroupsForKeyExchange(DefaultAllGroups);
            c.ConfigueSupportedSignatureSchemes(DefaultAllSignateSchemes);

            return c;
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
