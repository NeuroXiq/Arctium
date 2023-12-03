using Arctium.Standards.Connection.Tls13Impl.Model;

namespace Arctium.Standards.Connection.Tls13Impl.Model.Extensions
{

    /// <summary>
    /// rfc 6066
    /// </summary>
    class MaximumFragmentLengthExtensionExtension : Extension
    {
        public override ExtensionType ExtensionType => ExtensionType.MaxFragmentLength;

        public enum MaxFragmentLengthEnum
        {
            Length_2_9 = 1,
            Length_2_10 = 2,
            Length_2_11 = 3,
            Length_2_12 = 4
        }

        public MaxFragmentLengthEnum MaximumFragmentLength { get; private set; }

        public MaximumFragmentLengthExtensionExtension(MaxFragmentLengthEnum maxlen)
        {
            MaximumFragmentLength = maxlen;
        }
    }
}
