using System;
using Arctium.Standards.X501.Types;
using Arctium.Shared.Helpers.DataStructures;

namespace Arctium.Standards.X501.Mapping.Other
{
    public static class AttributeTypeStringAlias
    {
        static DoubleDictionary<string, AttributeType> saMap = new DoubleDictionary<string, AttributeType>();
        static DoubleDictionary<AttributeType, string[]> asMap = new DoubleDictionary<AttributeType,string[]>();

        public static AttributeType Get(string alias) => saMap[alias];
        public static string[] GetAllAliases(AttributeType type) => asMap[type];

        public static string GetFirstAlias(AttributeType type) => asMap[type][0];

        static AttributeTypeStringAlias()
        {
            Initialize();
        }

        private static void Initialize()
        {
            Insert(AttributeType.Country, "C");
            Insert(AttributeType.CommonName, "CN");
            Insert(AttributeType.DomainComponent, "DN");
            Insert(AttributeType.Email, "E");
            Insert(AttributeType.Email, "EMAIL");
            Insert(AttributeType.Email, "EMAILADDRESS");
            Insert(AttributeType.Locality, "L");
            Insert(AttributeType.Organization, "O");
            Insert(AttributeType.OrganizationalUnit, "OU");
            //Insert(AttributeType.PostalCode, "PC"); ????
            Insert(AttributeType.StateOrProvinceName, "S");
            Insert(AttributeType.StateOrProvinceName, "SP");
            // Insert(AttributeType.FamilyName, "SN"); ???
            //Insert(AttributeType.Street, "STREET");
            Insert(AttributeType.Title, "T");
        }

        private static void Insert(AttributeType type, string alias)
        {
            saMap[alias] = type;
            asMap[type] = new string[] { alias };
        }

        private static void Insert(AttributeType type, params string[] aliasArray)
        {
            foreach (string alias in aliasArray)
            {
                saMap[alias] = type;
            }
            asMap[type] = aliasArray;
        }
    }
}
        //// Helper holds relation of one key => many values e.g.
        //// AttributeType.EmailAddress = string[] { "E" , "EMAIL", "EMAILADDRESS" }
        //struct DictionaryEntry
        //{
        //    public AttributeType AttributeType;
        //    public string[] Values;

        //    public override bool Equals(object obj)
        //    {
        //        if (obj == null) return false;
        //        if (!(obj is DictionaryEntry)) return false;
        //        DictionaryEntry objAsEntry = (DictionaryEntry)obj;

        //        if (objAsEntry.AttributeType != this.AttributeType) return false;

        //        if (this.Values == null && objAsEntry.Values == null) return true;

        //        if (this.Values != null)
        //        {
        //            if (objAsEntry.Values != null)
        //            {
        //                for (int i = 0; i < this.Values.Length; i++)
        //                {
        //                    if (Values[i] == objAsEntry.Values[i]) return true;
        //                }

        //                return false;
        //            }
        //        }

        //        return false;
        //    }
        //}
                //smap["CN"] = new ObjectIdentifier(2, 5, 4, 3);
        //smap["SN"] = new ObjectIdentifier(2, 5, 4, 4);
        //smap["SERIALNUMBER"] = new ObjectIdentifier(2, 5, 4, 5);
        //smap["C"] = new ObjectIdentifier(2, 5, 4, 6);
        //smap["L"] = new ObjectIdentifier(2, 5, 4, 7);
        //smap["S"] = new ObjectIdentifier(2, 5, 4, 8);
        //// ?? smap["STREET"] = new ObjectIdentifier(2, 5, 4, 9);
        //smap["O"] = new ObjectIdentifier(2, 5, 4, 10);
        //smap["OU"] = new ObjectIdentifier(2, 5, 4, 11);
        //smap["TITLE"] = new ObjectIdentifier(2, 5, 4, 12);
        //smap["GN"] = new ObjectIdentifier(2, 5, 4, 42);
        //smap["E"] = new ObjectIdentifier(1, 2, 840, 113549, 1, 9, 1);
        //smap["UID"] = new ObjectIdentifier(0, 9, 2342, 19200300, 100, 1, 1);
        //smap["DC"] = new ObjectIdentifier(0, 9, 2342, 19200300, 100, 1, 25);