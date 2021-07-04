using System;
using System.Globalization;
using Arctium.Standards.ASN1.ObjectSyntax.Types;
using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Standards.ASN1.Serialization.Exceptions;

namespace Arctium.Standards.ASN1.Serialization.X690v2.DER.BuildInTypeDecoders
{
    public class GeneralizedTimeDecoder : IDerTypeDecoder<GeneralizedTime>
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
