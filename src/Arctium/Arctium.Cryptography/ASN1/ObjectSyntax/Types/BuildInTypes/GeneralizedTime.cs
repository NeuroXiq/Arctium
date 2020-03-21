using System;

namespace Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes
{
    public struct GeneralizedTime
    {
        public DateTime Value;

        public GeneralizedTime(DateTime value)
        {
            Value = value;
        }

        public static explicit operator DateTime(GeneralizedTime gTime) => gTime.Value;
        public static implicit operator GeneralizedTime(DateTime dateTime) => new GeneralizedTime(dateTime);
    }
}
