namespace Arctium.Connection.Tls.Tls13.Model.Extensions
{
    class SupportedVersionsExtension : Extension
    {
        public override ExtensionType ExtensionType => ExtensionType.SupportedVersions;

        public ushort SelectedVersion { get; private set; }

        public ushort[] Versions { get; private set; }

        public SupportedVersionsExtension(ushort[] versions)
        {
            this.Versions = versions;
        }

        public SupportedVersionsExtension(ushort selectedVersion)
        {
            SelectedVersion = selectedVersion;
        }
    }
}
