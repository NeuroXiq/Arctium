using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Serialization.X690;
using Arctium.Cryptography.ASN1.Serialization.X690.DER;
using Arctium.Cryptography.ASN1.Standards.X509.Model;
using Arctium.Shared.Helpers.Buffers;

namespace Arctium.Cryptography.ASN1.Standards.X509.Decoders.X690NodeDecoders
{
    class AlgorithmIdentifierModelNodeDecoder : IX690NodeDecoder<AlgorithmIdentifierModel>
    {
        public AlgorithmIdentifierModel Decode(X690DecodedNode node)
        {
            ObjectIdentifier algorithmId = DerDecoders.DecodeWithoutTag<ObjectIdentifier>(node[0]);
            byte[] parameters = null;

            if (node.ConstructedContent.Count == 2)
            {
                var parmsNode = node[1];
                if (parmsNode.Frame.Tag != BuildInTag.Null)
                {
                    // copy ALL der-encoded parameters bytes

                    long encodedParmsLength = parmsNode.ContentLength + parmsNode.Frame.FrameLength;
                    parameters = new byte[encodedParmsLength];
                    ByteBuffer.Copy(node.DataBuffer, node[1].FrameOffset, parameters, 0, encodedParmsLength);
                }
            }



            AlgorithmIdentifierModel algoIdModel = new AlgorithmIdentifierModel(algorithmId, parameters);

            return algoIdModel;
        }
    }
}
