﻿using Arctium.Standards.ASN1.ObjectSyntax.Types;
using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Standards.ASN1.Serialization.X690.BER.BuildInDecoders.Primitive;
using Arctium.Standards.ASN1.Serialization.X690v2.DER;
using System;
using System.Collections.Generic;
using ASN = Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;

/*
 * - Class info - 
 *  Contains implemented Der decoders in one place
 *  
 *  Have a Dictionary from typeof(SOME_ASN1_TYPE) => DER_DECODER
 * 
 */


namespace Arctium.Standards.ASN1.Serialization.X690.DER
{
    /// <summary>
    /// Contains DER decoders for build-in types. Gives possibility to decode DER data as ASN1 type with - or - without tags.
    /// </summary>
    public class DerDecoders
    {
        static Dictionary<Type, object> decoders = new Dictionary<Type, object>();

        static DerDecoders()
        {
            Initialize();
        }


        public static T DecodeWithoutTag<T>(X690DecodedNode node)
        {
            byte[] buffer = node.DataBuffer;
            IX690Decoder<T> decoder = (IX690Decoder<T>)decoders[typeof(T)];

            T decoded = decoder.Decode(buffer, node.ContentOffset, node.Frame.ContentLength.Length);

            return decoded;
        }

        public static TaggedType<T> DecodeWithTag<T>(X690DecodedNode node)
        {
            byte[] buffer = node.DataBuffer;
            if (node.Frame.Tag.Class != TagClass.Universal)
                throw new InvalidOperationException("Build in supports only universal tags but current tag is " + 
                    node.Frame.Tag.ToString());


            IX690Decoder<T> decoder = (IX690Decoder<T>)decoders[typeof(T)];
            long decodedLength;
            T decodedValue = decoder.Decode(buffer, node.ContentOffset, node.Frame.ContentLength.Length);

            TaggedType<T> decodedType = new TaggedType<T>(decodedValue, new Tag[] { node.Frame.Tag });

            return decodedType;
        }

        /// <summary>
        /// Decodes inner build-in type with EXPLICIT context specific tag
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="node"></param>
        /// <param name="buffer"></param>
        /// <returns></returns>
        public static TaggedType<T> DecodeWithECS<T>(X690DecodedNode node)
        {
            byte[] buffer = node.DataBuffer;
            IX690Decoder<T> decoder = ((IX690Decoder<T>)decoders[typeof(T)]);
            long codingLength;
            
            X690DecodedNode innerType = node.ConstructedContent[0];

            Tag contextSpecificTag = node.Frame.Tag;
            Tag typeTag = innerType.Frame.Tag;

            T decoded = decoder.Decode(buffer, innerType.ContentOffset, innerType.Frame.ContentLength.Length);

            Tag[] tags = new Tag[] { typeTag, contextSpecificTag };

            return new TaggedType<T>(decoded, tags);
        }

        /// <summary>
        /// Decodes content value of the EXPLICIT context-specific tagged type.
        /// </summary>
        /// <typeparam name="T">Content value type</typeparam>
        /// <param name="node">Coding node</param>
        /// <returns>Decoded content value</returns>
        public static T DecodeWithoutECS<T>(X690DecodedNode node)
        {
            var inner = node[0];
            IX690Decoder<T> decoder = (IX690Decoder<T>)decoders[typeof(T)];
            T decoded = decoder.Decode(node.DataBuffer, node.ContentOffset, node.ContentLength);

            return decoded;
        }


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
    }
}
