using Arctium.Shared.Other;
using System.Collections.Generic;
using System.Linq;

namespace Arctium.Standards.Connection.Tls.Tls13.API.Extensions
{
    public class ExtensionClientConfigSignatureAlgorithmsCert
    {
        public enum Action
        {
            /// <summary>
            /// If this result action is taken, certificate from server is validated.
            /// That means that server certificate signature must be one of listen in this extension.
            /// If servere provide signature other than listed in this extension, then handshake is aborted
            /// with fatal alert
            /// </summary>
            ForceServerCertificateMatchOrAbortHandshake,
            
            /// <summary>
            /// Not recommended
            /// If this result action is taken nothing special will happen.
            /// If server certificate match listed signatures, handshake continue.
            /// If server certificate do not match listed signatures, handshake continue without validation.
            /// </summary>
            IgnoreServerCertificateMatchAndContinueHandshake
        }

        internal Model.Extensions.SignatureSchemeListExtension.SignatureScheme[] SupportedSignatureSchemesCert { get; private set; }
        internal Action ClientAction { get; private set; }

        /// <summary>
        /// Initialize new instance of configuration. Action is equal to <see cref="Action.ForceServerCertificateMatchOrAbortHandshake"/>
        /// </summary>
        /// <param name="supportedSchemes"></param>
        public ExtensionClientConfigSignatureAlgorithmsCert(SignatureScheme[] supportedSchemes) :
            this(supportedSchemes, Action.ForceServerCertificateMatchOrAbortHandshake)
        {
        }

        /// <summary>
        /// Initialize new instance of confugration with supported schemes and action to be taken by client after receiving certificate.
        /// List of schemes must not be null or empty
        /// </summary>
        /// <param name="supportedSchemes">Supported signature schemes in X509 certificate from server</param>
        /// <param name="action">action to take X509 certificate from server match/not match with list in this configuration</param>
        public ExtensionClientConfigSignatureAlgorithmsCert(SignatureScheme[] supportedSchemes, Action action)
        {
            Validation.EnumValueDefined(supportedSchemes, nameof(supportedSchemes));
            Validation.EnumValueDefined(action, nameof(action));
            Validation.NotEmpty(supportedSchemes, nameof(supportedSchemes));

            SupportedSignatureSchemesCert = supportedSchemes.Select(s => (Model.Extensions.SignatureSchemeListExtension.SignatureScheme)s).ToArray();
            ClientAction = action;
        }
    }
}
