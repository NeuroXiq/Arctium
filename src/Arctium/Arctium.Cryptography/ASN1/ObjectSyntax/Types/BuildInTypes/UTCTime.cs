using System;

namespace Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes
{
    public struct UTCTime
    {
        private DateTime Value;

        public UTCTime(DateTime dateValue)
        {
            Value = dateValue;
        }

        public static explicit operator DateTime(UTCTime utcTime) => utcTime.Value;
        public static implicit operator UTCTime(DateTime dateTime) => new UTCTime(dateTime);
    }
}
