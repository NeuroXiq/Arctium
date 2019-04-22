using Arctium.Connection.Tls.RecordProtocol;
using System;

namespace Arctium.Connection.Tls.Operator
{
    class InvalidContentTypeException : Exception
    {
        public Record UnexpectedRecord { get; private set; }
        public ContentType ExpectedContentType { get; private set; }

        public InvalidContentTypeException(string message, ContentType expectedContentType, Record unexpectedRecord) : base(message)
        {
            UnexpectedRecord = unexpectedRecord;
            ExpectedContentType = expectedContentType;
        }
    }
}
