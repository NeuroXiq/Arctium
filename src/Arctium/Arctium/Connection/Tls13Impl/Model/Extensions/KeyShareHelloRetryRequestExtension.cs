using Arctium.Standards.Connection.Tls13Impl.Model;

namespace Arctium.Standards.Connection.Tls13Impl.Model.Extensions
{
    class KeyShareHelloRetryRequestExtension : Extension
    {
        public override ExtensionType ExtensionType => ExtensionType.KeyShare;

        public SupportedGroupExtension.NamedGroup SelectedGroup { get; private set; }

        public KeyShareHelloRetryRequestExtension(SupportedGroupExtension.NamedGroup selectedGroup)
        {
            SelectedGroup = selectedGroup;
        }
    }
}
