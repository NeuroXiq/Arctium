using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Exceptions;
using System;

namespace Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes
{
    public class UTCTime : Asn1TaggedType, IAsn1StrictType<DateTime>
    {
        public UTCTime(DateTime value) : base(BuildInTag.UTCTime)
        {
            TypedValue = value;
        }

        public override object Value { get { return TypedValue; } set { SetAsStrict(value); } }
        public DateTime TypedValue { get; set; }

        public void SetAsStrict(object value)
        {
            if (!(value is DateTime))
                throw InvalidStrictTypeException.Create<UTCTime, DateTime>(value);

            TypedValue = (DateTime)value;
        }
    }
}
