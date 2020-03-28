using System.Collections.Generic;
using Arctium.Cryptography.ASN1.ObjectSyntax.Types;
using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Serialization.X690;
using Arctium.Cryptography.ASN1.Serialization.X690.DER;
using Arctium.Cryptography.ASN1.Standards.X509.Exceptions;
using Arctium.Cryptography.ASN1.Standards.X509.Mapping.OID;
using Arctium.Cryptography.ASN1.Standards.X509.Model;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert.Extensions;

namespace Arctium.Cryptography.ASN1.Standards.X509.Decoders.X690NodeDecoders.ExtensionDecoders
{
    public class CertificatePolicyDecoder : IExtensionDecoder
    {
        DerDeserializer derDecoder = new DerDeserializer();
        X690Validation validation = new X690Validation(nameof(CertificatePolicyDecoder));
        public CertificateExtension DecodeExtension(ExtensionModel model)
        {
            byte[] rawData = model.ExtnValue.Value;
            X690DecodedNode decodedData = derDecoder.Deserialize(rawData)[0];

            List<PolicyInformation> policyInfos = new List<PolicyInformation>();

            //sequence of policies
            foreach (var policyNode in decodedData)
            {
                var mapedPolicy = DecodePolicy(policyNode);
                policyInfos.Add(mapedPolicy);
            }

            CertificatePoliciesExtension decodedPoliciesExtension
                = new CertificatePoliciesExtension(policyInfos.ToArray(), model.Critical);

            return decodedPoliciesExtension;
        }

        public PolicyInformation DecodePolicy(X690DecodedNode policyNode)
        {
            // sequence of 2 values: 
            // * [qualifierId]
            // * [ANY value] defined by qualifierId (2 variants possible defined by standard)

            validation.MinMax(policyNode, 1, 2);

            // must be 
            validation.Tag(policyNode, BuildInTag.Sequence, "CertificatePolicyDecoder");

            ObjectIdentifier policyInfoOid = DerDecoders.DecodeWithoutTag<ObjectIdentifier>(policyNode[0]);
            PolicyQualifierInfo[] policyQualifierInfos = null;

            // optional
            if (policyNode.ConstructedCount == 2)
            {
                validation.Tag(policyNode[1], BuildInTag.Sequence);
                policyQualifierInfos = DecodePolicyQualifiersInfos(policyNode[1]);
            }

            return new PolicyInformation(policyInfoOid, policyQualifierInfos);
        }

        public PolicyQualifierInfo[] DecodePolicyQualifiersInfos(X690DecodedNode sequenceNode)
        {
            List<PolicyQualifierInfo> decodedInfos = new List<PolicyQualifierInfo>();

            foreach (var infoNode in sequenceNode)
            {
                validation.CLength(infoNode, 2);
                var oidNode = infoNode[0];
                var qualifierNode = infoNode[1];

                validation.Tag(oidNode, BuildInTag.ObjectIdentifier);

                ObjectIdentifier qualifierOid = DerDecoders.DecodeWithoutTag<ObjectIdentifier>(oidNode);

                PolicyQualifierId policyQualifierId = PolicyQualifierIdOidMap.Get(qualifierOid);

                // qualifier can have 2 possible types
                if (policyQualifierId == PolicyQualifierId.CPS)
                {
                    validation.Tag(qualifierNode, BuildInTag.IA5String);
                    string cpsUriString = DerDecoders.DecodeWithoutTag<IA5String>(qualifierNode);
                    decodedInfos.Add(new PolicyQualifierInfo(cpsUriString));
                }
                else if (policyQualifierId == PolicyQualifierId.UserNotice)
                {
                    validation.Tag(qualifierNode, BuildInTag.Sequence);
                    UserNotice notice = DecodeNotice(qualifierNode);
                    decodedInfos.Add(new PolicyQualifierInfo(notice));
                }
                else throw new X509InternalException("Policyqualifierinfo, not found in enum", this);
            }

            return decodedInfos.ToArray();
        }

        public UserNotice DecodeNotice(X690DecodedNode userNoticeSequece)
        {
            validation.MinMax(userNoticeSequece, 0, 2);

            Tag[] displayTextTags = new Tag[] { BuildInTag.UTF8String, BuildInTag.IA5String };

            // deocded values
            // optiona -> can be null
            string decodedExpliticText = null;

            // optional
            // both null or both not null
            string decodedNoticeOrganization = null;
            byte[][] decodedNoticeNumbers = null;

            
            int count = userNoticeSequece.ConstructedCount;
            // both optional values are not present, return this ''empty'' object
            if (count == 0) return new UserNotice();
            else
            {
                int next = 0;

                // notice ref case
                if (userNoticeSequece[next].TagEqual(BuildInTag.Sequence))
                {
                    var noticeRefNode = userNoticeSequece[next];
                    validation.Tag(noticeRefNode, BuildInTag.Sequence);
                    validation.CLength(noticeRefNode, 2);
                    
                    // second must be a sequence of numbers 
                    validation.Tag(noticeRefNode[1], BuildInTag.Sequence);
                    var numbersSequence = noticeRefNode[1];

                    List<byte[]> numbers = new List<byte[]>();
                    foreach (var num in numbersSequence)
                    {
                        validation.Tag(num, BuildInTag.Integer);
                        Integer integer = DerDecoders.DecodeWithoutTag<Integer>(num);
                        numbers.Add(integer.BinaryValue);
                    }

                    decodedNoticeOrganization = GetDisplayText(noticeRefNode[0]);
                    decodedNoticeNumbers = numbers.ToArray();

                    next++;
                    if (next >= count) goto end;
                }

                // decoding explicitText 
                // must not bmp, visible string
                decodedExpliticText = GetDisplayText(userNoticeSequece[next]);

                
            }

        end:

            if (decodedExpliticText != null && decodedNoticeNumbers != null)
                return new UserNotice(decodedNoticeOrganization, decodedNoticeNumbers, decodedExpliticText);
            else if (decodedExpliticText != null)
                return new UserNotice(decodedExpliticText);
            else return new UserNotice(decodedNoticeOrganization, decodedNoticeNumbers);

        }

        public string GetDisplayText(X690DecodedNode node)
        {
            validation.AnyTags(node,
                    BuildInTag.IA5String,
                    BuildInTag.UTF8String);

            if (node.TagEqual(BuildInTag.IA5String))
                return DerDecoders.DecodeWithoutTag<IA5String>(node);
            else return DerDecoders.DecodeWithoutTag<UTF8String>(node);
        }
    }
}
