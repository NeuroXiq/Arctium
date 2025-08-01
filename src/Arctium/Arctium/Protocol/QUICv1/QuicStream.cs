//using Arctium.Standards.ASN1.Standards.X509.Mapping.OID;
//using Arctium.Protocol.QUICv1Impl;
//using System;
//using System.Collections.Generic;
//using System.Linq;
//using System.Text;
//using System.Threading.Tasks;

//namespace Arctium.Protocol.QUICv1
//{
//    public abstract class QuicStream
//    {
//        public abstract void WriteAsync();
//        public abstract long ReadAsync();
//        public abstract Task Reset();

//        /// <summary>
//        /// Abort and request closure
//        /// </summary>
//        public abstract void Close();
//    }
    
//    public class QuicSrvStream : QuicStream
//    {
//        QuicServerProtocol quicSrvProtocol;

//        public QuicSrvStream(DgramIO dgramio)
//        {
//            quicSrvProtocol = new QuicServerProtocol(dgramio);
//        }

//        public async Task ListenForConnectionAsync()
//        {
//            await quicSrvProtocol.ListenForConnectionAsync();
//            throw new NotImplementedException();
//        }

//        public override void WriteAsync()
//        {
//            throw new NotImplementedException();
//        }

//        public override long ReadAsync()
//        {
//            throw new NotImplementedException();
//        }

//        public override Task Reset()
//        {
//            throw new NotImplementedException();
//        }

//        public override void Close()
//        {
//            throw new NotImplementedException();
//        }
//    }
//}
