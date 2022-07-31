namespace Arctium.Connection.Tls.Tls13.Model.Extensions
{
    class NamedCurveListExtension : Extension
    {
        public override ExtensionType ExtensionType => ExtensionType.SupportedGroups;

        public enum NamedCurve : ushort
        {
            Deprecated = 1 /* 1 - 22*/,
            Secp256r1 = 23,
            Secp384r1 = 24,
            Secp521r1 = 25,
            X25519 = 29,
            X448 = 30,
            Reserved = 0xFE00, /* 0xFE00..0xFEFF */
            Deprecated2 = 0xFF01 /* 0xFF01..0xFF02 */
        }

        public NamedCurve[] NamedCurveList { get; private set; }

        public NamedCurveListExtension(NamedCurve[] namedCurveList)
        {
            NamedCurveList = namedCurveList;
        }
    }
}
