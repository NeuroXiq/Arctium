using Arctium.Shared.Other;
using Arctium.Standards.Connection.Tls.Tls13.Model.Extensions;
using System;

namespace Arctium.Standards.Connection.Tls.Tls13.API.Extensions
{
    /// <summary>
    /// RFC7301.
    /// Must select action, if no action taken then throws exception.
    /// Selector must invoke one of three methods that gain a result:
    /// <see cref="ExtensionServerALPN.NotSelectedFatalAlert"/>
    /// or <see cref="ExtensionServerALPN.NotSelectedIgnore"/>
    /// or <see cref="ExtensionServerALPN.Success(int)"/>
    /// </summary>
    public abstract class ExtensionServerConfigALPN
    {
        internal enum ResultType
        {
            Success,
            NotSelectedFatalAlert,
            NotSelectedIgnore
        }

        /// <summary>
        /// ALPN extension result selector, can select protocol or fail with alert
        /// </summary>
        public struct ResultSelect
        {
            int maxIndex;

            public ResultSelect(int maxIndex)
            {
                this.maxIndex = maxIndex;
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
                Validation.NumberInRange(index, 0, maxIndex, nameof(index), "index out of range of possible protocol list");

                return new Result(ResultType.Success, index);
            }
        }

        public struct Result
        {
            internal ResultType ActionType;
            internal int SelectedIndex;

            internal Result(ResultType type, int index)
            {
                Validation.Argument(index == -1 && type == ResultType.Success, nameof(index), "-1 only if not success");

                ActionType = type;
                SelectedIndex = index;
            }
        }

        public Result SelectorResult { get; private set; }

        public abstract Result Handle(byte[][] protocolNameListFromClient, ResultSelect resultSelector);
    }
}
