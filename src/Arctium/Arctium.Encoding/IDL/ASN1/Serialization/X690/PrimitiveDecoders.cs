using System;
using System.Collections.Generic;
using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types;
using Arctium.Encoding.IDL.ASN1.Serialization.Exceptions;

namespace Arctium.Encoding.IDL.ASN1.Serialization.X690
{
    public class PrimitiveDecoders
    {
        Dictionary<long, IPrimitiveDecoder> decodersMap;


        public PrimitiveDecoders()
        {
            decodersMap = new Dictionary<long, IPrimitiveDecoder>();
        }



        public void AddRange(IPrimitiveDecoder[] decoders)
        {
            foreach (var item in decoders)
            {
                decodersMap[TagHash(item.DecodesTag)] = item;
            }
        }

        public void Add(IPrimitiveDecoder decoder)
        {
            decodersMap[TagHash(decoder.DecodesTag)] = decoder;
        }

        public IPrimitiveDecoder Get(Tag tag)
        {
            long key = TagHash(tag);

            if (!decodersMap.ContainsKey(key))
            {
                throw new X690DeserializerException(null,
                    $"Primitive decoder for tag: {tag.ToString()} was not found." + 
                    "If this is not a build-in type, need to provide external primitive decoder to this Tag");
            }

            return decodersMap[TagHash(tag)];
        }

        private long TagHash(Tag tag)
        {
            long hash = 0;

            hash |= tag.Number << 4;
            hash |= (long)tag.Class << 59;

            return hash;
        }
    }
}
