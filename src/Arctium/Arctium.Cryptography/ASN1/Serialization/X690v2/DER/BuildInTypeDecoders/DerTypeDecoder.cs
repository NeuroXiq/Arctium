using System;
using System.Collections.Generic;
using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using ASN = Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;

namespace Arctium.Cryptography.ASN1.Serialization.X690v2.DER.BuildInTypeDecoders
{
    public class DerTypeDecoder
    {
        public byte[] Buffer { get; private set; }

        static Dictionary<Type, object> decoders = new Dictionary<Type, object>();

        public DerTypeDecoder(byte[] dataBuffer)
        {
            Buffer = dataBuffer;
        }

        static DerTypeDecoder()
        {
            Initialize();
        }


        public ASN.Boolean Boolean(DerDecoded derDecoded) => GenericDecoder<ASN.Boolean>(derDecoded);
        public Integer Integer(DerDecoded decoded) => GenericDecoder<Integer>(decoded);
        public ObjectIdentifier ObjectIdentifier(DerDecoded decoded) => GenericDecoder<ObjectIdentifier>(decoded);
        public BitString BitString(DerDecoded decoded) => GenericDecoder<BitString>(decoded);
        public PrintableString PrintableString(DerDecoded derDecoded) => GenericDecoder<PrintableString>(derDecoded);
        public UTF8String UTF8String(DerDecoded derDecoded) => GenericDecoder<UTF8String>(derDecoded);
        public UTCTime UTCTime(DerDecoded decoded) => GenericDecoder<UTCTime>(decoded);
        public UniversalString UniversalString(DerDecoded derDecoded) => GenericDecoder<UniversalString>(derDecoded);
        public IA5String IA5String(DerDecoded decoded) => GenericDecoder<IA5String>(decoded);
        public GeneralizedTime GeneralizedTime(DerDecoded decoded) => GenericDecoder<GeneralizedTime>(decoded);

        public OctetString OctetString(DerDecoded decoded) => GenericDecoder<OctetString>(decoded);

        private static void Initialize()
        {
            decoders[typeof(Integer)] = new IntegerDecoder();
            decoders[typeof(BitString)] = new BitstringDecoder();
            decoders[typeof(ObjectIdentifier)] = new ObjectIdentifierDecoder();
            decoders[typeof(UTCTime)] = new UTCTimeDecoder();
            decoders[typeof(GeneralizedTime)] = new GeneralizedTimeDecoder();
            decoders[typeof(PrintableString)] = new PrintableStringDecoder();
            decoders[typeof(UTF8String)] = new UTF8StringDecoder();
            decoders[typeof(ASN.Boolean)] = new BooleanDecoder();
            decoders[typeof(OctetString)] = new OctetStringDecoder();
            decoders[typeof(IA5String)] = new IA5StringDecoder();
        }

        private T GenericDecoder<T>(DerDecoded decoded)
        {
            return ((IDerTypeDecoder<T>)decoders[typeof(T)]).Decode(Buffer, decoded.ContentOffset, decoded.ContentLength);
        }
    }
}
