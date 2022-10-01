namespace Arctium.Standards.Connection.Tls.Tls13.Model.Extensions
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
