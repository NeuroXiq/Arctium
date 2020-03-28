using System;
using Arctium.Cryptography.ASN1.ObjectSyntax.Types;
using Arctium.Cryptography.ASN1.Serialization.X690.Exceptions;

namespace Arctium.Cryptography.ASN1.Serialization.X690
{
    /// <summary>
    /// Provides convenient way to validatie X690Decoded node, with expected tags, inner structures
    /// constructe length etc.
    /// </summary>
    public class X690Validation
    {
        string exceptionContext;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="exceptionContext">
        /// Name indicating context of exception throw (eg. class name).
        /// This string is included in exceptions messages
        /// </param>
        public X690Validation(string exceptionContext)
        {
            this.exceptionContext = exceptionContext;
            if (exceptionContext == null) exceptionContext = "";
        }

        /// <summary>
        /// If tag of the <paramref name="node"/> do not match <paramref name="expectedTag"/>
        /// throws exception
        /// </summary>
        /// <param name="node"></param>
        /// <param name="expectedTag"></param>
        /// <param name="additionalInfo"></param>
        public void Tag(X690DecodedNode node, Tag expectedTag, string additionalInfo = "")
        {
            if (!node.TagEqual(expectedTag))
            {
                string bufferData = FormatBufferData(node);
                string additionalMessage = exceptionContext + additionalInfo + " " + bufferData;

                throw UnexpectedTagException.Build(expectedTag, node.Frame.Tag, additionalMessage);
            }
        }

        /// <summary>
        /// If tags of the <paramref name="node"/> do not match any <paramref name="expectedTags"/>
        /// throws exception
        /// </summary>
        /// <param name="node"></param>
        /// <param name="expectedTag"></param>
        /// <param name="additionalInfo"></param>
        public void AnyTags(X690DecodedNode node, params Tag[] expectedTags)
        {
            foreach (var tag in expectedTags) if (node.TagEqual(tag)) return;

            string tagsString = "";
            foreach (var tag in expectedTags) tagsString += tag.ToString();

            string exceptionMesssage = BuildExceptionMessage(node,
                "Any tag do not match current decoded node. Valid tags: " +
                tagsString);

            throw new InvalidStructureException(exceptionMesssage);
        }

        /// <summary>
        /// Throws exception if node is not constructed or constucted length is not in a given range 
        /// </summary>
        /// <param name="node"></param>
        /// <param name="min"></param>
        /// <param name="max"></param>
        public void MinMax(X690DecodedNode node, int min, int max, string additionalInfo = "")
        {
            Constructed(node);
            if (node.ConstructedCount < min || node.ConstructedCount > max)
            {
                string msg = $"{exceptionContext}" +
                    $"Constructed content do not fit in provided range ({min}-{max})." +
                    $"{additionalInfo}. {FormatBufferData(node)}";

                throw new InvalidStructureException(msg);
            }
        }

        /// <summary>
        /// Throws exception if not constructed or constructed length do not match parameter length
        /// </summary>
        public void CLength(X690DecodedNode node, int length)
        {
            Constructed(node);
            if (node.ConstructedCount != length)
            {
                throw new InvalidStructureException(
                    BuildExceptionMessage(node,
                    $"Expected length of the inner values of constructed type: {length} " +
                    $"but current length: {node.ConstructedCount}"));
            }
        }

        public void Constructed(X690DecodedNode node)
        {
            if (node.Frame.PC != PCType.Constructed)
            {
                throw new NotConstructedException(FormatBufferData(node));
            }
        }

        private string BuildExceptionMessage(X690DecodedNode node,string message)
        {
            string msg = "X690Validation Exception: " + 
                $"Context: {exceptionContext}."+
                $"{message}." +
                $"{FormatBufferData(node)}.";

            return msg;
        }

        private string FormatBufferData(X690DecodedNode node)
        {
            string bufferData = "Buffer info: " +
                    $"'ContentOffset: {node.ContentOffset }, " +
                    $"Frame offset: {node.FrameOffset}'";

            return bufferData;
        }
    }
}
