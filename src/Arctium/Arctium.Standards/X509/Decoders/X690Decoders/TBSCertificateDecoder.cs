using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Standards.ASN1.Serialization.X690;
using Arctium.Standards.ASN1.Serialization.X690.DER;
using Arctium.Standards.ASN1.Standards.X509.Model;
using Arctium.Standards.ASN1.Standards.X509.Decoders.X690Decoders;
using System.Collections.Generic;
using ASN = Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Standards.ASN1.Serialization.X690v2.DER;
using Arctium.Standards.ASN1.Serialization.X690v2.DER.BuildInTypeDecoders;
using Arctium.Standards.X501.Decoders.X690Decoders;
using Arctium.Standards.ASN1.Serialization.Exceptions;

namespace Arctium.Standards.ASN1.Standards.X509.NodeDecoders.X690NodeDecoders
{
    public class TBSCertificateDecoder
    {
        ValidityDecoder validityDecoder = new ValidityDecoder();
        // AlgorithmIdentifierModelDecoder algoIdDecoder = new AlgorithmIdentifierModelDecoder();
        NameDecoder nameDecoder = new NameDecoder();

        public TBSCertificate Decode(DerDeserializedContext context)
        {
            var decoder = context.DerTypeDecoder;
            var node = context.Current;

            TBSCertificate tbs = new TBSCertificate();
            tbs.Version = decoder.Integer(node[0][0]);
            tbs.SerialNumber = decoder.Integer(node[1]);
            context.Current = node[2];
            tbs.Signature = AlgorithmIdentifierModelDecoder.Decode(context);
            tbs.Issuer = nameDecoder.Decode(decoder, node[3]);

            tbs.Validity = validityDecoder.Decode(decoder, node[4]);
            tbs.Subject = nameDecoder.Decode(decoder, node[5]);
            context.Current = node[6];
            tbs.SubjectPublicKeyInfo = DecodeSubjectPublicKeyInfo(context);

            // simulate, that all optionals are present
            int[] optionals = new int[10];
            long lastMin = -1;

            // optionals fields, find which are present 

            for (int i = 7; i < 10 && i < node.ConstructedCount; i++)
            {
                long current = node[i].Tag.Number;
                if (lastMin < current)
                {
                    lastMin = current;

                    // assign with some shift if previous optional values was not present.
                    // now, index of optional value (if value > 0) is storen in this array.
                    optionals[7 + current - 1] = i;
                }
                else throw new X690DecoderException("invalid order of the TBSCertificate fileds");
            }

            if (optionals[7] > 0)
                tbs.IssuerUniqueId = decoder.BitString(node[optionals[0]]);
            if (optionals[8] > 0)
                tbs.SubjectUniqueId = decoder.BitString(node[optionals[1]]);
            if (optionals[9] > 0)
            {
                // Explicitly tagged value. this node contains contructed type of before inner sequence of 
                // extensions
                // remove context-specific tag and get inner decoded node.

                var innerSequence = node[optionals[9]][0];
                tbs.Extensions = MapExtensions(decoder, innerSequence);
            }

            return tbs;
        }

        private ExtensionModel[] MapExtensions(DerTypeDecoder decoder, DerDecoded extSequenceNode)
        {
            List<ExtensionModel> extensions = new List<ExtensionModel>();

            foreach (var extNode in extSequenceNode)
            {
                ObjectIdentifier extId = decoder.ObjectIdentifier(extNode[0]);
                ASN.Boolean boolean = false;

                int extValueIndex = 1;

                // boolean can be present or can be ommitted.
                // if not present, default = false,
                // and next value are octet string

                if (extNode[1].Tag == BuildInTag.Boolean)
                {
                    extValueIndex++;
                    boolean = decoder.Boolean(extNode[1]);
                }

                OctetString extValue = decoder.OctetString(extNode[extValueIndex]);

                ExtensionModel model = new ExtensionModel(extId, boolean, extValue);
                extensions.Add(model);
            }

            return extensions.ToArray();
        }

        private PublicKeyInfoModel DecodeSubjectPublicKeyInfo(DerDeserializedContext context)
        {
            var current = context.Current;
            context.Current = current[0];
            var decoder = context.DerTypeDecoder;

            AlgorithmIdentifierModel algorithmIdentifier = AlgorithmIdentifierModelDecoder.Decode(context);
            BitString publicKey = decoder.BitString(current[1]);

            return new PublicKeyInfoModel(algorithmIdentifier, publicKey);
        }

       

        private BitString MapSignatureValue(X690DecodedNode x690DecodedNode)
        {
            BitString bitString = DerDecoders.DecodeWithoutTag<BitString>(x690DecodedNode);

            return bitString;

        }

        
    }
}
