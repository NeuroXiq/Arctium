namespace Arctium.Protocol.Tls13.Extensions
{
    /// <summary>
    /// Configuration of Server name extension RFC 6066 on Server side
    /// </summary>
    public abstract class ExtensionServerConfigServerName
    {
        public enum ResultAction
        {
            /// <summary>
            /// Server will continue handshake and server emptry extension 'server name list' to client
            /// </summary>
            Success,

            /// <summary>
            /// Server will abort handshake with 'unrecognized name (112)' fatal alert
            /// </summary>
            AbortFatalAlertUnrecognizedName,

            /// <summary>
            /// Do nothing, server wil not send 'Server name' extension to client
            /// </summary>
            Ignore
        }

        /// <summary>
        /// Extension handler must implement this method to return action what server should do next
        /// </summary>
        /// <param name="hostNames">ASCII list of host names from client hello</param>
        /// <returns>Action what server should do server</returns>
        public abstract ResultAction Handle(byte[] hostName);
    }
}
