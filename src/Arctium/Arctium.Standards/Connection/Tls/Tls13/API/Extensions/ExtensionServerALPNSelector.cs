using Arctium.Shared.Other;
using Arctium.Standards.Connection.Tls.Tls13.Model.Extensions;
using System;

namespace Arctium.Standards.Connection.Tls.Tls13.API.Extensions
{
    /// <summary>
    /// RFC7301.
    /// Must select action, if no action taken then throws exception.
    /// Selector must invoke one of three methods that gain a result:
    /// <see cref="ExtensionServerALPNSelector.NotSelectedFatalAlert"/>
    /// or <see cref="ExtensionServerALPNSelector.NotSelectedIgnore"/>
    /// or <see cref="ExtensionServerALPNSelector.Success(int)"/>
    /// </summary>
    public class ExtensionServerALPNSelector
    {
        internal enum ResultType
        {
            Success,
            NotSelectedFatalAlert,
            NotSelectedIgnore
        }

        public struct Result
        {
            internal ResultType ActionType;
            internal int SelectedIndex;

            internal Result(ResultType type, int index)
            {
                ActionType = type;
                SelectedIndex = index;
            }
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
        /// Will reject connection with no_application_protocol alert fatal.
        /// This result will reject client attempt to connect
        /// </summary>
        public Result NotSelectedFatalAlert()
        {
            return new Result(ResultType.NotSelectedFatalAlert, -1);
        }

        /// <summary>
        /// Server will not send response to this extension and it will be ignored.
        /// Handshake will continue like without ALPN extension from client
        /// </summary>
        public Result NotSelectedIgnore()
        {
            return new Result(ResultType.NotSelectedIgnore, -1);
        }

        /// <summary>
        /// Server will send ALPN extension response with selected protocol.
        /// </summary>
        /// <param name="index"></param>
        public Result Success(int index)
        {
            Validation.NumberInRange(index, 0, ProtocolNameListFromClient.Length - 1, nameof(index),
                "Index out of range. Index must be valid index to point to 'ProtocolNameListFromClient' value");

            return new Result(ResultType.Success, index);
        }
    }
}
