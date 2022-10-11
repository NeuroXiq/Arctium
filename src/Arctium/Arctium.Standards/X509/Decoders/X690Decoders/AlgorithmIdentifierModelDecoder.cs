using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Standards.ASN1.Serialization.X690v2.DER;
using Arctium.Standards.ASN1.Serialization.X690v2.DER.BuildInTypeDecoders;
using Arctium.Standards.ASN1.Standards.X509.Model;
using Arctium.Shared.Helpers.Buffers;

namespace Arctium.Standards.ASN1.Standards.X509.Decoders.X690Decoders
{
    class AlgorithmIdentifierModelDecoder
    {
        public AlgorithmIdentifierModel Decode(DerDeserializedContext context)
        {
            var decoder = context.DerTypeDecored;
            var decoded = context.Current;

            ObjectIdentifier algorithmId = decoder.ObjectIdentifier(decoded[0]);
            byte[] parameters = null;

            if (decoded.ConstructedCount == 2)
            {
                var parmsNode = decoded[1];
                if (parmsNode.Tag != BuildInTag.Null)
                {
                    // copy ALL der-encoded parameters bytes
                    parameters = new byte[decoded[1].Length];
                    MemCpy.Copy(decoder.Buffer, decoded[1].Offset, parameters, 0, decoded[1].Length);
                }
            }



            AlgorithmIdentifierModel algoIdModel = new AlgorithmIdentifierModel(algorithmId, parameters);

            return algoIdModel;
        }
    }
}
