using Arctium.Shared.Other;
using Arctium.Standards.Connection.Tls.Tls13.Model.Extensions;

namespace Arctium.Standards.Connection.Tls.Tls13.API.Extensions
{
    /// <summary>
    /// RFC7301
    /// </summary>
    public class ExtensionServerALPNSelector
    {
        public enum Result
        {
            Success,
            NotSelectedFatalAlert,
            NotSelectedIgnore,
        }

        /// <summary>
        /// Protcol list received from client
        /// </summary>
        public byte[][] ProtocolNameListFromClient { get; private set; }
        public int SuccessIndex { get; private set; }
        public Result SelectorResult { get; private set; }

        internal ExtensionServerALPNSelector(byte[][] protocolNameListFromClient)
        {
            this.ProtocolNameListFromClient = protocolNameListFromClient;
        }

        /// <summary>
        /// Some protcol names are already defined with constant values.
        /// Method tries to get constant value defined by IANA.
        /// If protocol name was found returns it in out parameter
        /// otherwise out param is set to null and return false
        /// </summary>
        /// <param name="protocolName">protocol name utf-8 raw bytes from client</param>
        /// <param name="outprotocol">result or null if not foud</param>
        /// <returns>true if found false if not found</returns>
        public static bool TryGetStandarizedProtocolName(byte[] protocolName, out ALPNProtocol? outprotocol)
        {
            outprotocol = null;

            ProtocolNameListExtension.Protocol? internalResult;
            if (ProtocolNameListExtension.TryGetByBytes(protocolName, out internalResult))
            {
                outprotocol = (ALPNProtocol)(outprotocol.Value);
            }

            return false;
        }

        /// <summary>
        /// Will reject connection with no_application_protocol alert fatal
        /// </summary>
        public void NotSelectedFatalAlert()
        {
            SelectorResult = Result.NotSelectedFatalAlert;
        }

        /// <summary>
        /// Server will not send response to this extension and it will be ignored.
        /// Handshake will continue like without ALPN extension from client
        /// </summary>
        public void NotSelectedIgnore()
        {
            SelectorResult = Result.NotSelectedIgnore;
        }

        /// <summary>
        /// Server will send ALPN extension response with selected protocol.
        /// </summary>
        /// <param name="index"></param>
        public void Success(int index)
        {
            Validation.NumberInRange(index, 0, ProtocolNameListFromClient.Length - 1, nameof(index),
                "Index out of range. Index must be valid index to point to 'ProtocolNameListFromClient' value");

            SuccessIndex = index;
            SelectorResult = Result.Success;
        }
    }
}
