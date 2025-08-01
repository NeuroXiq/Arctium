using Arctium.Shared;
using Arctium.Protocol.Tls13Impl.Model.Extensions;
using System;

namespace Arctium.Protocol.Tls13.Extensions
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

            /// <summary>
            /// Will reject connection with no_application_protocol alert fatal.
            /// This result will reject client attempt to connect
            /// </summary>
            public static Result NotSelectedFatalAlert()
            {
                return new Result(ResultType.NotSelectedFatalAlert, -1);
            }

            /// <summary>
            /// Server will not send response to this extension and it will be ignored.
            /// Handshake will continue like without ALPN extension from client
            /// </summary>
            public static Result NotSelectedIgnore()
            {
                return new Result(ResultType.NotSelectedIgnore, -1);
            }

            /// <summary>
            /// Server will send ALPN extension response with selected protocol.
            /// </summary>
            /// <param name="index"></param>
            public static Result Success(int index)
            {
                return new Result(ResultType.Success, index);
            }
        }

        public abstract Result Handle(byte[][] protocolNameListFromClient);
    }
}
