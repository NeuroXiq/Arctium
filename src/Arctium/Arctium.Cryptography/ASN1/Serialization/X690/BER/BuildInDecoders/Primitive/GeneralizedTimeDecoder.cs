using System;
using System.Globalization;
using Arctium.Cryptography.ASN1.ObjectSyntax.Types;
using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Serialization.Exceptions;
using Arctium.Cryptography.ASN1.Serialization.X690.DER;

namespace Arctium.Cryptography.ASN1.Serialization.X690.BER.BuildInDecoders.Primitive
{
    public class GeneralizedTimeDecoder : IX690Decoder<GeneralizedTime>
    {
        const int LengthWithoutTimeOffset = 13;
        const int LengthWithTimeOffset = 18;
        const string PatterLocalOffsetNotPresent = "yyyyMMddHHmmssZ";
        const string PatternLocalOffsetPresent = "yyyyMMddHHmmssK";

        public Tag DecodesTag { get { return BuildInTag.UTCTime; } }

        public GeneralizedTime Decode(byte[] buffer, long offset, long length)
        {
            
            if (length != LengthWithTimeOffset && length != LengthWithoutTimeOffset)
                throw new X690DecoderException("Invalid UTCTime string. UTCTime string do not have a valid length ");

            string timeString = System.Text.Encoding.ASCII.GetString(buffer, (int)offset, (int)length);
            DateTime parsedDate;

            try
            {
                if (length == LengthWithoutTimeOffset)
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
                    $" Cannot parse Time string, current value: {timeString}");
            }

            var type = new GeneralizedTime(parsedDate);
            return type;
        }
    }
}
