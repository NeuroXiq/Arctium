using System;
using System.Globalization;
using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types;
using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Encoding.IDL.ASN1.Serialization.Exceptions;
using Arctium.Encoding.IDL.ASN1.Serialization.X690.DER;

namespace Arctium.Encoding.IDL.ASN1.Serialization.X690.BER.BuildInDecoders.Primitive
{
    public class UTCTimeDecoder : IPrimitiveDecoder
    {
        const int LengthWithoutOffset = 13;
        const int LengthWithOffset = 18;
        const string PatterLocalOffsetNotPresent = "yyMMddhhmmssZ";
        const string PatternLocalOffsetPresent = "yyMMddhhmmssK";

        public Tag DecodesTag { get { return BuildInTag.UTCTime; } }

        

        public Asn1TaggedType Decode(CodingFrame frame, byte[] buffer, long offset, out long contentLength)
        {
            contentLength = frame.ContentLength.Length;
            if (contentLength != LengthWithOffset && contentLength != LengthWithoutOffset)
                throw new X690DecoderException("Invalid UTCTime string. UTCTime string do not have a valid length ", this);

            string timeString = System.Text.Encoding.ASCII.GetString(buffer, (int)offset, (int)contentLength);
            DateTime parsedDate;

            try
            {
                if (contentLength == LengthWithoutOffset)
                {
                    parsedDate = DateTime.ParseExact(timeString, PatterLocalOffsetNotPresent, CultureInfo.InvariantCulture);
                }
                else
                {
                    parsedDate = DateTime.ParseExact(timeString, PatternLocalOffsetPresent, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
                }
            }
            catch (FormatException)
            {
                throw new X690DecoderException("Invalid UTCTime string." + 
                    $" Cannot parse Time string, current value: {timeString}", this);
            }

            Asn1TaggedType type = new UTCTime(parsedDate);
            return type;
        }
    }
}
