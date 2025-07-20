using Arctium.Shared.Other;
using Arctium.Standards.Connection.Tls13;
using System.Linq;
using Arctium.Standards.Connection.Tls13Impl.Model.Extensions;

namespace Arctium.Standards.Connection.Tls13.Extensions
{
    /// <summary>
    /// Configures 'Signature Algorithms Cert' TLS 13 extension (RFC 8446)
    /// </summary>
    public class ExtensionClientConfigSignatureAlgorithmsCert
    {
        //public enum Action
        //{
        //    /// <summary>
        //    /// If this result action is taken, certificate from server is validated.
        //    /// That means that server certificate signature must be one of listen in this extension.
        //    /// If servere provide signature other than listed in this extension, then handshake is aborted
        //    /// with fatal alert
        //    /// </summary>
        //    ForceServerCertificateMatchOrAbortHandshake,

        //    /// <summary>
        //    /// Not recommended
        //    /// If this result action is taken nothing special will happen.
        //    /// If server certificate match listed signatures, handshake continue.
        //    /// If server certificate do not match listed signatures, handshake continue without validation.
        //    /// </summary>
        //    IgnoreServerCertificateMatchAndContinueHandshake
        //}

        internal SignatureSchemeListExtension.SignatureScheme[] SupportedSignatureSchemesCert { get; private set; }
        // internal Action ClientAction { get; private set; }

        /// <summary>
        /// Initialize new instance of configuration.
        /// </summary>
        /// <param name="supportedSchemes"></param>
        //public ExtensionClientConfigSignatureAlgorithmsCert(SignatureScheme[] supportedSchemes) : this(supportedSchemes)
        //{
        //}

        /// <summary>
        /// Initialize new instance of confugration with supported schemes
        /// List of schemes must not be null or empty
        /// </summary>
        /// <param name="supportedSchemes">Supported signature schemes that will be sent in client hello to server</param>
        public ExtensionClientConfigSignatureAlgorithmsCert(SignatureScheme[] supportedSchemes)
        {
            Validation.EnumValueDefined(supportedSchemes, nameof(supportedSchemes));
            Validation.NotEmpty(supportedSchemes, nameof(supportedSchemes));

            SupportedSignatureSchemesCert = supportedSchemes.Select(s => (SignatureSchemeListExtension.SignatureScheme)s).ToArray();
        }
    }
}
