using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Serialization.X690;
using Arctium.Cryptography.ASN1.Serialization.X690.DER;
using Arctium.Cryptography.ASN1.Standards.X509.Model;
using X500D = Arctium.Cryptography.ASN1.Standards.X501.Decoders.X690NodeDecoders;
using Arctium.Cryptography.ASN1.Standards.X509.Decoders.X690NodeDecoders;
using Arctium.Cryptography.ASN1.ObjectSyntax.Types;
using System;
using System.Collections.Generic;
using ASN = Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;

namespace Arctium.Cryptography.ASN1.Standards.X509.NodeDecoders.X690NodeDecoders
{
    public class TBSCertificateNodeDecoder : IX690NodeDecoder<TBSCertificate>
    {
        ValidityNodeDecoder validityDecoder = new ValidityNodeDecoder();
        AlgorithmIdentifierModelNodeDecoder algoIdDecoder = new AlgorithmIdentifierModelNodeDecoder();
        X500D.NameNodeDecoder nameDecoder = new X500D.NameNodeDecoder();



        public TBSCertificate Decode(X690DecodedNode node)
        {
            TBSCertificate tbs = new TBSCertificate();
            tbs.Version = DerDecoders.DecodeWithECS<Integer>(node[0]).Value;
            tbs.SerialNumber = DerDecoders.DecodeWithoutTag<Integer>(node[1]);
            tbs.Signature = algoIdDecoder.Decode(node[2]);
            tbs.Issuer = nameDecoder.Decode(node[3]);
            tbs.Validity = validityDecoder.Decode(node[4]);
            tbs.Subject = nameDecoder.Decode(node[5]);
            tbs.SubjectPublicKeyInfo = MapSubjectPublicKeyInfo(node[6]);

            int next = 7;

            if (node[next].Frame.Tag == Tag.ContextSpecific(1))
            {
                next++;
                tbs.IssuerUniqueId = DerDecoders.DecodeWithoutTag<BitString>(node[7]);
            }
            if (node[next].Frame.Tag == Tag.ContextSpecific(2))
            {
                tbs.SubjectUniqueId = DerDecoders.DecodeWithoutTag<BitString>(node[next]);
                next++;
            }
            if (node[next].Frame.Tag == Tag.ContextSpecific(3))
            {
                // Explicitly tagged value. this node contains contructed type of before inner sequence of 
                // extensions
                // remove context-specific tag and get inner decoded node.

                var innerSequence = node[next][0];
                tbs.Extensions = MapExtensions(innerSequence);
                next++;
            }

            return tbs;
        }

        private ExtensionModel[] MapExtensions(X690DecodedNode extSequenceNode)
        {
            List<ExtensionModel> extensions = new List<ExtensionModel>();

            foreach (var extNode in extSequenceNode)
            {
                ObjectIdentifier extId = DerDecoders.DecodeWithoutTag<ObjectIdentifier>(extNode[0]);
                ASN.Boolean boolean = false;

                int extValueIndex = 1;

                // boolean can be present or can be ommitted.
                // if not present, default = false,
                // and next value are octet string

                if (extNode[1].Frame.Tag == BuildInTag.Boolean)
                {
                    extValueIndex++;
                    boolean = DerDecoders.DecodeWithoutTag<ASN.Boolean>(extNode[1]);
                }

                OctetString extValue = DerDecoders.DecodeWithoutTag<OctetString>(extNode[extValueIndex]);

                ExtensionModel model = new ExtensionModel(extId, boolean, extValue);
                extensions.Add(model);
            }

            return extensions.ToArray();
        }

        private SubjectPublicKeyInfoModel MapSubjectPublicKeyInfo(X690DecodedNode node)
        {
            AlgorithmIdentifierModel algorithmIdentifier = algoIdDecoder.Decode(node[0]);
            BitString publicKey = DerDecoders.DecodeWithTag<BitString>(node[1]).Value;

            return new SubjectPublicKeyInfoModel(algorithmIdentifier, publicKey);
        }

       

        private BitString MapSignatureValue(X690DecodedNode x690DecodedNode)
        {
            BitString bitString = DerDecoders.DecodeWithoutTag<BitString>(x690DecodedNode);

            return bitString;

        }

        
    }
}
