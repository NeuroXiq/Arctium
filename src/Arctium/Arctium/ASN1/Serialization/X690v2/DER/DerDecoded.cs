using Arctium.Standards.ASN1.ObjectSyntax.Types;
using System.Collections;
using System.Collections.Generic;
using Arctium.Shared;

namespace Arctium.Standards.ASN1.Serialization.X690v2.DER
{
    public struct DerDecoded : IEnumerable<DerDecoded>
    {
        public long Offset;
        public long Length;
        public long ContentOffset;
        public long ContentLength;
        public bool IsConstructed;
        public DArray<DerDecoded> Constructed;
        public long ConstructedCount { get { return Constructed.Count; } }
        public Tag Tag;

        public DerDecoded this[int index] { get { return Constructed[index]; } }

        public DerDecoded(Tag curTag, long offset, long length, bool isConstructed, long contentOffset, long contentLength)
        {
            Tag = curTag;
            Offset = offset;
            Length = length;
            IsConstructed = isConstructed;
            ContentOffset = contentOffset;
            ContentLength = contentLength;
            Constructed = null;
        }

        public override string ToString()
        {
            if(!IsConstructed) return Tag.ToString();

            string result = Tag.ToString() + ": [ ";

            for (int i = 0; i < 10 && i < Constructed.Count; i++)
            {
                result += Constructed[i].Tag.ToString() + ", ";
            }

            return result + "] ";

        }

        public IEnumerator<DerDecoded> GetEnumerator()
        {
            return Constructed.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return Constructed.GetEnumerator();
        }
    }
}
