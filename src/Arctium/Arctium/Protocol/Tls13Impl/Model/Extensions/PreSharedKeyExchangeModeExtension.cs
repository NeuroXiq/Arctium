using System.Collections.Generic;
using Arctium.Protocol.Tls13Impl.Model;

namespace Arctium.Protocol.Tls13Impl.Model.Extensions
{
    class PreSharedKeyExchangeModeExtension : Extension
    {
        public enum PskKeyExchangeMode : byte
        {
            PskKe = 0,
            PskDheKe = 1
        }

        public override ExtensionType ExtensionType => ExtensionType.PskKeyExchangeModes;

        public List<PskKeyExchangeMode> KeModes { get; private set; }

        public PreSharedKeyExchangeModeExtension(PskKeyExchangeMode[] keModes)
        {
            KeModes = new List<PskKeyExchangeMode>(keModes);
        }
    }
}
