using Arctium.Standards.Connection.Tls.Tls13.API.Extensions;

namespace Arctium.Standards.Connection.Tls.Tls13.API
{
    public class Tls13ServerConnectionInfo
    {
        public ExtensionResultALPN ExtensionResultALPN { get; private set; }

        internal Tls13ServerConnectionInfo(Protocol.Tls13ServerProtocol.ConnectedInfo internalConnInfo)
        {
            if (internalConnInfo.ExtensionResultALPN != null)
                ExtensionResultALPN = new ExtensionResultALPN(internalConnInfo.ExtensionResultALPN);
        }
    }
}
