using Arctium.Cryptography.ASN1.ObjectSyntax.Types;
using Arctium.Cryptography.ASN1.Serialization.X690.DER;
using System.Collections;
using System.Collections.Generic;

namespace Arctium.Cryptography.ASN1.Serialization.X690
{
    public class X690DecodedNode : IEnumerable<X690DecodedNode>
    {
        public byte[] DataBuffer;
        public CodingFrame Frame;
        public long FrameOffset;
        public long ContentOffset { get { return FrameOffset + Frame.FrameLength; } }
        public long ContentLength;

        public List<X690DecodedNode> ConstructedContent;

        public X690DecodedNode this[int i] { get { return ConstructedContent[i]; } }

        public X690DecodedNode()
        {

        }

        public void AppendConstructorContent(X690DecodedNode decodedNode)
        {
            ConstructedContent.Add(decodedNode);
        }

        public IEnumerator<X690DecodedNode> GetEnumerator()
        {
            return ConstructedContent.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return ConstructedContent.GetEnumerator();
        }
    }
}
