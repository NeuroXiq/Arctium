using Arctium.DllGlobalShared.Helpers.DataStructures;
using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes;

namespace Arctium.Encoding.IDL.ASN1.Standards.X501.Mapping
{
    public class AttributeTypeMapper
    {
        public DoubleDictionary<string, ObjectIdentifier> map;

        public AttributeTypeMapper()
        {
            map = new DoubleDictionary<string, ObjectIdentifier>();


            CreateMappings();
        }

        public string this[ObjectIdentifier oid] => map[oid];

        public void CreateMappings()
        {
            map["CN"] = new ObjectIdentifier(2, 5, 4, 3);
            map["SN"] = new ObjectIdentifier(2, 5, 4, 4);
            map["SERIALNUMBER"] = new ObjectIdentifier(2, 5, 4, 5);
            map["C"] = new ObjectIdentifier(2, 5, 4, 6);
            map["L"] = new ObjectIdentifier(2, 5, 4, 7);
            map["S"] = new ObjectIdentifier(2, 5, 4, 8);
            map["STREET"] = new ObjectIdentifier(2, 5, 4, 9);
            map["O"] = new ObjectIdentifier(2, 5, 4, 10);
            map["OU"] = new ObjectIdentifier(2, 5, 4, 11);
            map["TITLE"] = new ObjectIdentifier(2, 5, 4, 12);
            map["GN"] = new ObjectIdentifier(2, 5, 4, 42);
            map["E"] = new ObjectIdentifier(1, 2, 840, 113549, 1, 9, 1);
            map["UID"] = new ObjectIdentifier(0, 9, 2342, 19200300, 100, 1, 1);
            map["DC"] = new ObjectIdentifier(0, 9, 2342, 19200300, 100, 1, 25);
        }

        public bool Contains(string value) => map.ContainsKey(value);
        public bool Contains(ObjectIdentifier oid) => map.ContainsKey(oid);
    }
}