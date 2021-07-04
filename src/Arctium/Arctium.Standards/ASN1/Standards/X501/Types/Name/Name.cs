using Arctium.Standards.ASN1.Standards.X501.Mapping.Other;
using System;
using System.Collections.Generic;

namespace Arctium.Standards.ASN1.Standards.X501.Types
{
    /// <summary>
    /// Represents Name type of X500 standart. Name consists of set of <see cref="AttributeTypeAndValue"/> 
    /// </summary>
    public struct Name
    {
        public enum FormatStringMode
        {
            Classic,
            EnumName,
        }

        public NameType NameType { get; private set; }

        public object innerValue { get; private set; }

        internal Name(NameType type, object innerValue)
        {
            //choince type, currently only 1 possibility but prepared for updates
            this.innerValue = innerValue;
            this.NameType = type;
        }

        public RelativeDistinguishedName[] GetAsRelativeDistinguishedNames()
        {
            return (RelativeDistinguishedName[])innerValue;
        }

        public override string ToString()
        {
            return this.ToString(FormatStringMode.Classic);
        }

        public string ToString(FormatStringMode formatType)
        {
            if (formatType != FormatStringMode.Classic) throw new NotSupportedException($"now supports onlyl {FormatStringMode.Classic.ToString()} mode");

            List<string> converted = new List<string>();

            foreach (var at in GetAsRelativeDistinguishedNames())
            {
                converted.Add(at.ToString());
            }

            string result = string.Join(", ", converted.ToArray());

            return result;
        }
    }
}
