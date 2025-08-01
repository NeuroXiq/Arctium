using System;

namespace Arctium.Protocol.Tls13.Messages
{
    /// <summary>
    /// Configuration object for Post handshake client authentication on server side
    /// </summary>
    public abstract class ServerConfigPostHandshakeClientAuthentication : ServerConfigHandshakeClientAuthentication
    {
        /// <summary>
        /// Event args for <see cref="ClientAuthSuccess"/> event
        /// </summary>
        public class ClientAuthSuccessEventArgs
        {
            /// <summary>
            /// Client certificates. Can be empty (if configuration allows
            /// accept client with no certificate) or can have one or more certificates.
            /// First certificate (index 0 ) is client certificate 
            /// other certificates (other than index 0) are certificate path.
            /// Order of other certificates may be random or next can sign previous.
            /// </summary>
            public byte[][] ClientCertificates;
            public ReadOnlyMemory<byte> InstanceId;

            internal ClientAuthSuccessEventArgs(byte[][] certs, ReadOnlyMemory<byte> instanceId)
            {
                ClientCertificates = certs;
                InstanceId = instanceId;
            }
        }

        /// <summary>
        /// Fired when client authentication completed successfully
        /// </summary>
        public event EventHandler<ClientAuthSuccessEventArgs> ClientAuthSuccess;

        /// <summary>
        /// Called by internal implementation of protocol. When success
        /// then it will fire success event.
        /// </summary>
        internal void OnClientAuthSuccess(byte[][] clientCerts, ReadOnlyMemory<byte> instanceId)
        {
            ClientAuthSuccess?.Invoke(this, new ClientAuthSuccessEventArgs(clientCerts, instanceId));
        }
    }
}
