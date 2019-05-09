using Arctium.Connection.Tls.Operator.Tls11Operator;
using Arctium.Connection.Tls.Protocol.RecordProtocol;
using Arctium.Connection.Tls.ProtocolStream.RecordsLayer;
using System;
using System.IO;

namespace Arctium.Connection.Tls.Operator
{
    class TlsProtocolOperatorSwitch
    {
        public static TlsProtocolOperator OpenServerSession(Stream innerStream)
        {
            RecordIO recordIO = new RecordIO(innerStream);
            recordIO.LoadRecord();
            RecordHeader recordHeader = recordIO.RecordHeader;

            if (recordHeader.Version.Major == 3)
            {
                if (recordHeader.Version.Minor >= 1)
                {
                    return Tls11ProtocolOperator.CreateServerSession(recordIO);
                }
                else throw new NotSupportedException("Version not supported by this implemnetation of tls");
            }
            else throw new System.Exception("unknow Major version");
        }
    }
}