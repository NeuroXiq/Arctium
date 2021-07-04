using System;
using System.Globalization;
using Arctium.Standards.ASN1.ObjectSyntax.Types;
using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Standards.ASN1.Serialization.Exceptions;

namespace Arctium.Standards.ASN1.Serialization.X690v2.DER.BuildInTypeDecoders
{
    public class UTCTimeDecoder : IDerTypeDecoder<UTCTime>
    {
        const int LengthWithoutTimeOffset = 13;
        const int LengthWithTimeOffset = 18;
        const string PatterLocalOffsetNotPresent = "yyMMddHHmmssZ";
        const string PatternLocalOffsetPresent = "yyMMddHHmmssK";

        public Tag DecodesTag { get { return BuildInTag.UTCTime; } }

        public UTCTime Decode(byte[] buffer, long offset, long contentLength)
        {
            int codingLength = (int)contentLength;
            if (codingLength != LengthWithTimeOffset && codingLength != LengthWithoutTimeOffset)
                throw new X690DecoderException("Invalid UTCTime string. UTCTime string do not have a valid length ");

            string timeString = System.Text.Encoding.ASCII.GetString(buffer, (int)offset, (int)codingLength);
            DateTime parsedDate;

            try
            {
                if (codingLength == LengthWithoutTimeOffset)
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

            var type = new UTCTime(parsedDate);
            return type;
        }
    }
}
