using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types;
using Arctium.Encoding.IDL.ASN1.Serialization.Exceptions;
using Arctium.Encoding.IDL.ASN1.Serialization.X690.DER;
using System.Collections.Generic;

namespace Arctium.Encoding.IDL.ASN1.Serialization.X690
{
    public class ConstructorDecoders
    {
        Dictionary<long, IConstructorDecoder> decodersMap;


        public ConstructorDecoders()
        {
            decodersMap = new Dictionary<long, IConstructorDecoder>();
        }

        public void Add(IConstructorDecoder constructorDecoder)
        {
            decodersMap.Add(TagHash(constructorDecoder.DecodesTag), constructorDecoder); 
        }

        public void AddRange(IConstructorDecoder[] decoders)
        {
            foreach (var item in decoders)
            {
                decodersMap[TagHash(item.DecodesTag)] = item;
            }
        }

        public IConstructorDecoder Get(Tag tag)
        {
            return decodersMap[TagHash(tag)];
        }

        public IConstructorDecoder Create(Tag tag, CodingFrame frame)
        {
            if (!decodersMap.ContainsKey(TagHash(tag)))
                throw new X690DeserializerException(null, $"Cannot find ContructorDecoder for {tag.ToString()}.\n" +
                    "If this is not a build in type, this constructor decoder should be added as an external decoder");
            return decodersMap[TagHash(tag)].Create(frame);
        }

        private long TagHash(Tag tag)
        {
            long hash = 0;
            hash |= (long)tag.Class << 60;
            hash |= (long)tag.Number;

            return hash;
        }
    }
}
