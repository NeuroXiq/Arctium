using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;
using System;

namespace Arctium.Standards.ASN1.ObjectSyntax.Types
{
    public struct Tag
    {
        public TagClass Class { get; private set; }
        public byte[] FullNumber { get; private set; }
        public long Number { get; private set; }
        public object EncodingReference { get; private set; }

        public Tag(TagClass tagClass, long number, object er = null)
        {
            Class = tagClass;
            Number = number;
            FullNumber = null;
            EncodingReference = er;
        }

        public Tag(TagClass tagClass, byte[] number, object er = null)
        {
            throw new NotSupportedException("long (as byte[] array) tag number are not supported");
        }


        public override string ToString()
        {
            string formatted = "";

            string className = Enum.GetName(typeof(TagClass), Class);
            string numName = "";
            string classNo = ((long)Class).ToString();
            string numNo = Number.ToString();
                
            if (Class == TagClass.Universal)
            {
                numName = Enum.GetName(typeof(Asn1Type), Number);
            }
            else
            {
                numName = Number.ToString();
            }

            return $"{className}:{numName} ({classNo}, {numNo})";
        }

        public static Tag ContextSpecific(long number)
        {
            return new Tag(TagClass.ContextSpecific, number);
        }

        public override bool Equals(object obj)
        {
            bool result = false;
            if (obj is Tag)
            {
                Tag tag = (Tag)obj;
                result = tag.Class == this.Class &&
                    tag.Number == this.Number;
            }

            return result;
        }

        public static bool operator !=(Tag a, Tag b)
        {
            return !a.Equals(b);
        }

        public static bool operator ==(Tag a, Tag b)
        {
            return a.Equals(b);
        }
    }
}
