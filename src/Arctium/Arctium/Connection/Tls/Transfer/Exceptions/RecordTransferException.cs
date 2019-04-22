using System;

namespace Arctium.Connection.Tls.Transfer
{
    class RecordTransferException : Exception
    {
        public RecordTransferException(string message) : base(message)
        {
        }
    }
}
