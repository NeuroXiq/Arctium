namespace Arctium.Connection.Tls.Tls13.Model.Extensions
{
    class SupportedVersionsExtension : Extension
    {
        public override ExtensionType ExtensionType => ExtensionType.SupportedVersions;

        public const ushort TLS13Version = 0x0304;

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

        public static SupportedVersionsExtension ServerHelloTls13()
        {
            return new SupportedVersionsExtension(TLS13Version);
        }
    }
}
