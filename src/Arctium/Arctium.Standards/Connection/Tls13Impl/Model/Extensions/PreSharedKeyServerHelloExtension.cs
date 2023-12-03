using Arctium.Standards.Connection.Tls13Impl.Model;

namespace Arctium.Standards.Connection.Tls13Impl.Model.Extensions
{
    internal class PreSharedKeyServerHelloExtension : Extension
    {
        public override ExtensionType ExtensionType => ExtensionType.PreSharedKey;

        public ushort SelectedIdentity { get; private set; }

        public PreSharedKeyServerHelloExtension(ushort selectedIdentity)
        {
            SelectedIdentity = selectedIdentity;
        }
    }
}
