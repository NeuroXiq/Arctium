using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types;
using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Encoding.IDL.ASN1.Standards.X501.Types;
using Arctium.Encoding.IDL.ASN1.Standards.X509.Model;
using Arctium.Encoding.IDL.ASN1.Standards.X509.Types.Model;
using Arctium.Encoding.IDL.ASN1.Standards.X509.Validation;
using System;
using System.Collections.Generic;
using static Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.Asn1TaggedTypeHelper;
using X509Types = Arctium.Encoding.IDL.ASN1.Standards.X509.Types;
using ASN1Type = Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Encoding.IDL.ASN1.Standards.X509.Types;


/* - Class info -
 * 
 * Mapping from a decoded, raw asn.1 objects (sequence, integer, bistring etc.) 
 * to 'X509CertifiacateModel' object.
 * 
 * It gets asn1. objects and reassign them to concrete 
 * fileds in x509certificate object eg:
 * from some 'sequence', values are extracted and assigned to a 'tbsCertificate' property
 * 
 * helper methods like 'Is', 'AsSpecific' are importet as static in using statement
 * 
 */


namespace Arctium.Encoding.IDL.ASN1.Standards.X509.Mapping
{
    public class X509ModelMapper
    {
        X509CertificateAsn1StructureValidator structureValidator;

        public X509ModelMapper()
        {
            structureValidator = new X509CertificateAsn1StructureValidator();
        }

        public X509CertificateModel MapFromResult(List<Asn1TaggedType> rootDecodingContainer)
        {
            X509StructureValidationResult validationResult;
            if (!structureValidator.ValidateStructure(rootDecodingContainer).Success)
            {
                throw new Exception();
            }

            var root = rootDecodingContainer[0];
            var rootSequence = AsSpecific<Sequence>(root);
            var rootList = rootSequence.TypedValue;

            var tbsCertSeq = rootList[0];
            var signatureAlgoSeq = rootList[1];
            var signatureValue = rootList[2];

            TBSCertificate tbsCert = MapTbsCertificate(AsSpecific<Sequence>(tbsCertSeq));
            AlgorithmIdentifierModel algoIdentifier = MapAlgorithmIdentifier(signatureAlgoSeq);
            BitString sigValue = AsSpecific<BitString>(signatureValue);

            X509CertificateModel certModel = new X509CertificateModel(tbsCert, algoIdentifier, sigValue);

            return certModel;
        }

        private TBSCertificate MapTbsCertificate(Sequence tbsCertSeq)
        {
            var tbsList = tbsCertSeq.TypedValue;

            var version = AsSpecific<X509Types::Version>(tbsList[0]);
            var serialNumber = AsSpecific<Integer>(tbsList[1]);
            var signature = MapAlgorithmIdentifier(tbsList[2]);
            var issuer = MapAttributeTypeAndValueSequenceOfSets(tbsList[3]);
            var validity = MapValidity(tbsList[4]);
            var subject = MapAttributeTypeAndValueSequenceOfSets(tbsList[5]);
            var subjectPubKeyInfo = MapSubjectPublicKeyInfo(tbsList[6]);

            // TODO ASN1/X509 this values must be a new Tagged types with implemented decoders.
            // Not working now
            //BitString issuerUniqueId, subjectUniqueId;

            // optional fields

            //int nextIndex = 7;
            //
            //if (Is(tbsList[7], X509Type.IssuerUniqueIdTag))
            //{
            //    issuerUniqueId = AsSpecific<BitString>(tbsList[nextIndex]);
            //    nextIndex++;
            //}
            //if (Is(tbsList[nextIndex], X509Type.SubjectUniqueIdTag))
            //{
            //    subjectUniqueId = AsSpecific<BitString>(tbsList[nextIndex]);
            //    nextIndex++;
            //}
            //if (Is(tbsList[nextIndex], X509Type.ExtensionsTag))
            //{
            //
            //}

            ExtensionModel[] extensions = null;

            int last = tbsList.Count - 1;
            if (last > 6)
            {
                if(Is(tbsList[last], X509Type.ExtensionsTag))
                    extensions = GetExtensions(tbsList[last]);
            }

            TBSCertificate mappedTbsCert = new TBSCertificate();
            mappedTbsCert.Version = version;
            mappedTbsCert.SerialNumber = serialNumber;
            mappedTbsCert.Signature = signature;
            mappedTbsCert.Issuer = issuer;
            mappedTbsCert.Validity = validity;
            mappedTbsCert.Subject = subject;
            mappedTbsCert.SubjectPublicKeyInfo = subjectPubKeyInfo;
            mappedTbsCert.Extensions = extensions;

            return mappedTbsCert;
        }

        private ExtensionModel[] GetExtensions(Asn1TaggedType asn1TaggedType)
        {
            var extensionsType = AsSpecific<X509Types.Extensions>(asn1TaggedType);
            var extensionsList = extensionsType.TypedValue.TypedValue;
            var mappedExtensions = new List<ExtensionModel>();

            foreach (var ext in extensionsList)
            {
                mappedExtensions.Add(MapExtension(ext));
            }

            return mappedExtensions.ToArray();
        }

        private ExtensionModel MapExtension(Asn1TaggedType ext)
        {
            var extFields = AsSpecific<Sequence>(ext).TypedValue;

            var extId = AsSpecific<ObjectId>(extFields[0]);
            ASN1Type.Boolean critical = null;
            ASN1Type.OctetString extnValue = null;

            int nextIndex = 1;

            if (Is<ASN1Type::Boolean>(extFields[1]))
            {
                critical = AsSpecific<ASN1Type.Boolean>(extFields[1]);
                nextIndex++;
            }
            else critical = new ASN1Type.Boolean(false); // default value if not present

            extnValue = AsSpecific<OctetString>(extFields[nextIndex]);
            ExtensionModel mappedExtention = new ExtensionModel(extId, critical, extnValue);

            return mappedExtention;
        }

        private SubjectPublicKeyInfoModel MapSubjectPublicKeyInfo(Asn1TaggedType value)
        {
            List<Asn1TaggedType> values = AsSpecific<Sequence>(value).TypedValue;

            var algorithm = MapAlgorithmIdentifier(values[0]);
            var subjectPubKey = AsSpecific<BitString>(values[1]);

            return new SubjectPublicKeyInfoModel(algorithm, subjectPubKey);
        }

        private Validity MapValidity(Asn1TaggedType asn1TaggedType)
        {
            var periodsSequence = AsSpecific<Sequence>(asn1TaggedType);
            var valuesList = periodsSequence.TypedValue;

            DateTime start = AsSpecific<UTCTime>(valuesList[0]).TypedValue;
            DateTime end = AsSpecific<UTCTime>(valuesList[1]).TypedValue;

            return new Validity(start, end);
        }

        private AttributeTypeAndValue[] MapAttributeTypeAndValueSequenceOfSets(Asn1TaggedType tvPairContainer)
        {
            Sequence containerSequence = AsSpecific<Sequence>(tvPairContainer);
            var values = containerSequence.TypedValue;
            List<AttributeTypeAndValue> mapped = new List<AttributeTypeAndValue>();

            foreach (var tv in values)
            {
                var tvPairMapped = MapAttributeTypeAndValueFromSet(AsSpecific<Set>(tv));
                mapped.Add(tvPairMapped);
            }

            return mapped.ToArray();
        }

        private void Throw(string message)
        {
            throw new X509FormatException(message, this);
        }

        private AttributeTypeAndValue MapAttributeTypeAndValueFromSet(Set tvSet)
        {
            // set contains single sequence object which contains 2 data fields
            // sequence [ set [ sequence { type,value }], set [ sequence {type, value}], set [ sequence {type,value}]  .... ]
            var pairAsList = AsSpecific<Sequence>(tvSet.TypedValue[0]).TypedValue;
            
            var type = AsSpecific<ObjectId>(pairAsList[0]);
            var value = pairAsList[1];

            return new AttributeTypeAndValue(type, value);
        }

        private AlgorithmIdentifierModel MapAlgorithmIdentifier(Asn1TaggedType signatureAlgoSeq)
        {
            List<Asn1TaggedType> values = (signatureAlgoSeq as Sequence).TypedValue;

            var oid = AsSpecific<ObjectId>(values[0]);
            Asn1TaggedType parameters = values[1];

            AlgorithmIdentifierModel identifier = new AlgorithmIdentifierModel(oid, parameters);

            return identifier;
        }
    }
}
