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

        public OnCCSState(RecordLayer12 recordLayer)
        {
            this.recordLayer = recordLayer;
        }

        public ChangeCipherSpec Read()
        {
            ContentType type;
            FragmentData data = recordLayer.ReadFragment(out type);

            if (type != ContentType.ChangeCipherSpec) throw new Exception("expected change cipher spec");

            if (data.Length != 1) throw new Exception("invalid length of ccs fragment message");

            byte[] buf = new byte[1];
            data.Copy(buf, 0);



            if (((byte)ChangeCipherSpecType.ChangeCipherSpec != buf[0])) throw new Exception("Invalid change cipher spec value");

            return new ChangeCipherSpec() { CCSType = ChangeCipherSpecType.ChangeCipherSpec };
        }
    }
}
