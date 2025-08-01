using Arctium.Shared;
using Arctium.Protocol.Tls13Impl.Model.Extensions;

namespace Arctium.Protocol.Tls13.Extensions
{
    /// <summary>
    /// Represents object that stores informations about selected
    /// ALPN protocol by server
    /// </summary>
    public class ExtensionResultALPN
    {
        /// <summary>
        /// Selected protocol by server as raw bytes
        /// </summary>
        public byte[] Protocol { get; private set; }


        /// <summary>
        /// creates new instance of object with specified protocol.
        /// selected protocol means selected protocol by server in ALPN negotiation extension
        /// </summary>
        /// <param name="selectedByServer"></param>
        internal ExtensionResultALPN(byte[] selectedByServer)
        {
            Validation.NotEmpty(selectedByServer, nameof(selectedByServer), "this is impossible by specification");
            Protocol = selectedByServer;
        }

        /// <summary>
        /// Some protcol names are already defined with constant values.
        /// Method tries to get constant value defined by IANA.
        /// If protocol name was found returns it in out parameter
        /// otherwise out param is set to null and return false
        /// </summary>
        /// <param name="alpnProtocolNameRawBytes">protocol name utf-8 raw bytes from client</param>
        /// <param name="outprotocol">result or null if not found</param>
        /// <returns>true if found false if not found</returns>
        public static bool TryGetAsStandarizedALPNProtocol(byte[] alpnProtocolNameRawBytes, out ALPNProtocol? outStandarizedProtocol)
        {
            ProtocolNameListExtension.Protocol? outInternalValue;

            if (ProtocolNameListExtension.TryGetByBytes(alpnProtocolNameRawBytes, out outInternalValue))
            {
                outStandarizedProtocol = (ALPNProtocol?)outInternalValue.Value;
                return true;
            }

            outStandarizedProtocol = null;
            return false;
        }
    }
}
