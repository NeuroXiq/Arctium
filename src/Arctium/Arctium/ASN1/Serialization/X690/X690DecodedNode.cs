using Arctium.Standards.ASN1.ObjectSyntax.Types;
using Arctium.Standards.ASN1.Serialization.X690.DER;
using System;
using System.Collections;
using System.Collections.Generic;

namespace Arctium.Standards.ASN1.Serialization.X690
{
    public class X690DecodedNode : IEnumerable<X690DecodedNode>
    {
        /// <summary>
        /// Pointer for encoded data array
        /// </summary>
        public byte[] DataBuffer;
        public CodingFrame Frame;
        public long FrameOffset;
        public long ContentOffset { get { return FrameOffset + Frame.FrameLength; } }
        public long ContentLength;
        public int ConstructedCount { get { return ConstructedContent.Count; } }

        public List<X690DecodedNode> ConstructedContent;

        public X690DecodedNode this[int i]
        {
            get
            {
                return ConstructedContent[i];
            }
        }

        public X690DecodedNode()
        {

        }

        public void AppendConstructorContent(X690DecodedNode decodedNode)
        {
            ConstructedContent.Add(decodedNode);
        }

        /// <summary>
        /// Indicates if current decoded node contains context-specific tag of a given number in <seealso cref="ConstructedContent"/> list
        /// </summary>
        /// <param name="contextSpecificTagNumber">Context specific tag number to search</param>
        /// <returns></returns>
        public bool HaveCS(int contextSpecificTagNumber)
        {
            if (ConstructedContent == null) return false;
            if (ConstructedContent.Count == 0) return false;

            Tag specificTag = Tag.ContextSpecific(contextSpecificTagNumber);

            foreach (var node in ConstructedContent)
            {
                if (node.TagEqual(specificTag)) return true;
            }

            return false;
        }

        /// <summary>
        /// Get context-specific tagged node for a given tag number in current constructor type
        /// </summary>
        /// <param name="contextSpecificTagNumber">Context specific tag number</param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException">If current type is not a constructor</exception>
        /// <exception cref="KeyNotFoundException">If value was not found in constructor list</exception>
        public X690DecodedNode GetCSNode(int contextSpecificTagNumber)
        {
            if (Frame.PC != PCType.Constructed)
                throw new InvalidOperationException("Cannot get any inner node because current decoded node is not a constructed-type");

            Tag specificTag = Tag.ContextSpecific(contextSpecificTagNumber);

            foreach (var node in ConstructedContent)
            {
                if (node.TagEqual(specificTag)) return node;
            }

            throw new KeyNotFoundException("Cannot find provided context-specific tag in current constructed context");
        }

        /// <summary>
        /// Indicates if current tag node is equal to provided node
        /// </summary>
        /// <param name="tag">Tag to compare</param>
        /// <returns>If tags are equal returns true otherwise returns false</returns>
        public bool TagEqual(Tag tag)
        {
            return tag == Frame.Tag;
        }

        public IEnumerator<X690DecodedNode> GetEnumerator()
        {
            return ConstructedContent.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return ConstructedContent.GetEnumerator();
        }

#if DEBUG
        public override string ToString()
        {
            // for debug purposes (when cursor hover this class) 
            // values (if type is constructed) are shown and are easy to see 
            // instead of searching what is in constructed list (and unwinding object tree)

            string constructedContent = "";
            int i = 0;
            if (Frame.PC == PCType.Constructed)
            {

                foreach (var item in this)
                {
                    if (i > 10) break;
                    constructedContent += item.Frame.Tag.ToString() + " | ";
                    i++;
                }
                
            }
            else
            {
                constructedContent = "<not_constructed>";
            }

            return Frame.Tag.ToString() + $" => " + constructedContent;
        }
#endif
    }
}
