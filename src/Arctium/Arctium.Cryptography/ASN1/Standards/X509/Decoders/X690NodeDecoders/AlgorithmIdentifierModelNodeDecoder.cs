using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Serialization.X690;
using Arctium.Cryptography.ASN1.Serialization.X690.DER;
using Arctium.Cryptography.ASN1.Standards.X509.Model;
using Arctium.Shared.Helpers.Buffers;
using System;
using System.Collections.Generic;
using System.Text;

namespace Arctium.Cryptography.ASN1.Standards.X509.Decoders.X690NodeDecoders
{
    public class AlgorithmIdentifierModelNodeDecoder : IX690NodeDecoder<AlgorithmIdentifierModel>
    {
        public AlgorithmIdentifierModel Decode(X690DecodedNode node)
        {
            ObjectIdentifier algorithmId = DerDecoders.DecodeWithoutTag<ObjectIdentifier>(node[0]);
            byte[] parameters = null;

            if (node.ConstructedContent.Count == 2)
            {
                if (node[1].Frame.Tag != BuildInTag.Null)
                {
                    long len = node[1].ContentLength;
                    parameters = new byte[len];
                    ByteBuffer.Copy(node.DataBuffer, node[1].FrameOffset, parameters, 0, len);
                }
            }



            AlgorithmIdentifierModel algoIdModel = new AlgorithmIdentifierModel(algorithmId, parameters);

            return algoIdModel;
        }
    }
}
