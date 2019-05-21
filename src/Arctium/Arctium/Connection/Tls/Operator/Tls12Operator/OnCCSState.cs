using Arctium.Connection.Tls.Protocol.BinaryOps.Builder;
using Arctium.Connection.Tls.Protocol.ChangeCipherSpecProtocol;
using Arctium.Connection.Tls.Protocol.RecordProtocol;
using Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer12;
using System;

namespace Arctium.Connection.Tls.Operator.Tls12Operator
{
    class OnCCSState
    {
        RecordLayer12 recordLayer;
        byte[] readBuffer = new byte[0x4800 + 2048];

        public OnCCSState(RecordLayer12 recordLayer)
        {
            this.recordLayer = recordLayer;
        }

        public ChangeCipherSpec Read()
        {
            ContentType type;
            int readed = recordLayer.ReadFragment(readBuffer,0,out type);

            if (type != ContentType.ChangeCipherSpec) throw new Exception("expected change cipher spec");

            if (readed != 1) throw new Exception("invalid length of ccs fragment message");

            if (((byte)ChangeCipherSpecType.ChangeCipherSpec != readBuffer[0])) throw new Exception("Invalid change cipher spec value");

            return new ChangeCipherSpec() { CCSType = ChangeCipherSpecType.ChangeCipherSpec };
        }

        public void Write()
        {
            //formatting is so simple (is only 1 bytes of value 1) that can be hardcoded
            byte[] ccsBytes = new byte[] { 1 };
            recordLayer.Write(ccsBytes, 0, 1, ContentType.ChangeCipherSpec);
        }
    }
}
