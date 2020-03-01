//using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types;
//using Arctium.Encoding.IDL.ASN1.Serialization.X690.BER;

//namespace Arctium.Encoding.IDL.ASN1.Serialization.Exceptions
//{
//    public class UnexpectedDecodingTypeException : BerDeserializerException
//    {
//        public Tag ExpectedTag { get; private set; }

//        public Tag CurrentTag { get; private set; }

//        public UnexpectedDecodingTypeException(Tag expected, Tag current, string message, BerDecodingContext context) : base(message, context)
//        {
//            ExpectedTag = expected;
//            CurrentTag = current;
//        }

//        public static UnexpectedDecodingTypeException Create(Tag expected, Tag current, BerDecodingContext ctx, string msg = "")
//        {
//            string message = "Unexpected tag. " +
//                            $"Expected {expected.ToString()}" +
//                            $"but got {current.ToString()}";

//            return new UnexpectedDecodingTypeException(expected, current, message, ctx);
//        }
//    }
//}
