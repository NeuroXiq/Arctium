using System;

namespace Arctium.Connection.Tls.Tls13.API
{
    public class Tls13Exception : Exception
    {
        public Tls13Exception(string messageName, string fieldName, string error) : base(FormatMessage(messageName, fieldName, error))
        {
        }

        public Tls13Exception(string error) : base(error) { }

        static string FormatMessage(string messageName, string fieldName, string error)
        {
            string text = string.Empty;

            if (messageName != null) text += $"MESSAGE_NAME: {messageName}";
            if (fieldName != null) text += $"FIELD_NAME: {fieldName}";
            if (error != null) text += $"ERROR: {error}";

            return text;
        }
    }
}
