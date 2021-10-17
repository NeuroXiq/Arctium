using Arctium.Standards.X501.Mapping.Other;
using System.Collections.Generic;

namespace Arctium.Standards.X501.Types
{
    public struct RelativeDistinguishedName
    {
        public AttributeTypeAndValue[] AttributeTypeAndValues;

        public RelativeDistinguishedName(AttributeTypeAndValue[] attributeTypeAndValues)
        {
            AttributeTypeAndValues = attributeTypeAndValues;
        }

        public override string ToString()
        {
            List<string> converted = new List<string>();

            foreach (var at in AttributeTypeAndValues)
            {
                string alias = AttributeTypeStringAlias.GetFirstAlias(at.Type);
                string formatted = $"{alias}={at.ToString()}";
                converted.Add(formatted);
            }

            // ??? 
            string result = string.Join("_", converted.ToArray());

            return result;
        }
    }
}
