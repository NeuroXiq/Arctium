namespace Arctium.Standards.Connection.Tls.Tls13.Model.Extensions
{
    class PreSharedKeyExchangeModeExtension : Extension
    {
        public enum PskKeyExchangeMode : byte
        {
            PskKe = 0,
            PskDheKe = 1
        }

        public override ExtensionType ExtensionType => ExtensionType.PskKeyExchangeModes;

        public PskKeyExchangeMode[] KeModes { get; private set; }

        public PreSharedKeyExchangeModeExtension(PskKeyExchangeMode[] keModes)
        {
            KeModes = keModes;
        }
    }
}
