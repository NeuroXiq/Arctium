using Arctium.Cryptography.ASN1.Standards.X500.Mapping.Other;
using System;
using System.Collections.Generic;

namespace Arctium.Cryptography.ASN1.Standards.X500.Types
{
    /// <summary>
    /// Represents Name type of X500 standart. Name consists of set of <see cref="AttributeTypeAndValue"/> 
    /// </summary>
    public struct Name
    {
        public enum FormatString
        {
            Default,
            EnumName,
        }


        public AttributeTypeAndValue[] AttributeTypeAndValues;

        public Name(AttributeTypeAndValue[] atvList)
        {
            AttributeTypeAndValues = atvList;
        }

        public override string ToString()
        {
            return ToString(FormatString.Default);
        }

        public string ToString(FormatString formatType)
        {
            if (formatType != FormatString.Default) throw new NotSupportedException("now supports onlyl default mode");

            List<string> converted = new List<string>();

            foreach (var at in AttributeTypeAndValues)
            {
                string alias = AttributeTypeStringAlias.GetFirstAlias(at.Type);
                string formatted = $"{alias}={at.StringValue()}";
                converted.Add(formatted);
            }

            string result = string.Join(", ", converted.ToArray());

            return result;
        }
    }
}
