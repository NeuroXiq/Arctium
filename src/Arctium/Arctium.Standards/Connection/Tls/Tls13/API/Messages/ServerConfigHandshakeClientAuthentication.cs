using Arctium.Standards.Connection.Tls.Tls13.API.APIModel;
using System.Collections.Generic;

namespace Arctium.Standards.Connection.Tls.Tls13.API.Messages
{
    /// <summary>
    /// Configuration for Client authentication in handshake
    /// </summary>
    public abstract class ServerConfigHandshakeClientAuthentication
    {
        public enum Action
        {
            /// <summary>
            /// Server will continue with current client certificate.
            /// If certificate was provided by client, server will validate certificate verify from client.
            /// If certificate was not provided by client (empty byte array) server will continue without client certificate.
            /// </summary>
            Success,

            /// <summary>
            /// When certificate is required but not received certificate from client
            /// </summary>
            AlertFatalCertificateRequired = 116,
            AlertFatalUnknownCa = 48,
            AlertFatalCertificateUnknown = 46,
            AlertFatalCertificateExpired = 45,
            AlertFatalUnsupportedCertificate = 43,
            AlertFatalBadCertificate = 42,
        }

        /// <summary>
        /// Invoked when certificate was received from client. Returns action what server should do next
        /// </summary>
        /// <param name="certificateFromClient">Array can be empty because client can send empty certificate (if client don't want to auth by cert)</param>
        /// <returns>Action to do by server</returns>
        public abstract Action CertificateFromClientReceived(byte[][] certificateFromClient, List<Extension> extensions);
    }
}
