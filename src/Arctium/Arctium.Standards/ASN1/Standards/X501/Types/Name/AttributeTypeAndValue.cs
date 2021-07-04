using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;
using System;

namespace Arctium.Standards.ASN1.Standards.X501.Types
{
    public struct AttributeTypeAndValue
    {
        public AttributeType Type;
        object value;

        internal AttributeTypeAndValue(AttributeType type, object value)
        {
            Type = type;
            this.value = value;
        }

        public AttributeTypeAndValue(AttributeType type, string value)
        {
            Type = type;
            this.value = value;
        }

        /// <summary>
        /// Returns value of <see cref="AttributeTypeAndValue"/> pair
        /// </summary>
        /// <returns></returns>
        public string StringValue()
        {
            if (value is PrintableString) return (PrintableString)value;
            else if (value is UTF8String) return (UTF8String)value;
            else throw new NotSupportedException("Name (x509) Not supported to string conversion");
        }

        public override string ToString()
        {
            return value.ToString();
        }
    }
}
