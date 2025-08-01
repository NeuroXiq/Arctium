using System;

namespace Arctium.Protocol.Tls13Impl.Protocol
{
    internal class Tls13Exception : Exception
    {
        public Tls13Exception(string messageName, string fieldName, string error, Exception innerException) :
            base(FormatMessage(messageName, fieldName, error), innerException)
        { }

        public Tls13Exception(string messageName, string fieldName, string error) : this(messageName, fieldName, error, null)
        {
        }

        public Tls13Exception(string error) : base(error) { }

        static string FormatMessage(string messageName, string fieldName, string error)
        {
            string text = string.Empty;

            if (messageName != null) text += $"MESSAGE_NAME: {messageName}; ";
            if (fieldName != null) text += $"FIELD_NAME: {fieldName}; ";
            if (error != null) text += $"ERROR: {error}; ";

            return text;
        }
    }
}
