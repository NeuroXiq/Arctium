using Arctium.Standards.Connection.Tls.Tls13.API.Extensions;

namespace Arctium.Standards.Connection.Tls.Tls13.API
{
    public class Tls13ServerConnectionInfo
    {
        public ExtensionResultALPN ExtensionResultALPN { get; private set; }
        
        /// <summary>
        /// If Server extension was configured stores action taken by server by current cofiguration for this extension.
        /// If extesnion was not configures value is null
        /// </summary>
        public ExtensionServerConfigServerName.ResultAction? ExtensionResultServerName { get; private set; }

        internal Tls13ServerConnectionInfo(Protocol.Tls13ServerProtocol.ConnectedInfo internalConnInfo)
        {
            if (internalConnInfo.ExtensionResultALPN != null)
                ExtensionResultALPN = new ExtensionResultALPN(internalConnInfo.ExtensionResultALPN);

            ExtensionResultServerName = internalConnInfo.ExtensionResultServerName;
        }
    }
}
