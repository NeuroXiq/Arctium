using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using System;

namespace Arctium.Connection.Tls.Operator.Tls11Operator
{
    class Tls11ClientOperator
    {
        Tls11ClientActionType currentActionType;
        Tls11ClientSendAction currentSendActionType;
        Tls11ClientWaitAction currentWaitActionType;

        Handshake currentReceivedHandshakeMessage;
        HandshakeMessages11 exchangedHandshakeMessages;

        public void OpenNewSession()
        {
            OpenClientSessionTransition();
        }

        public void OpenClientSessionTransition()
        {
            currentActionType = Tls11ClientActionType.Send;
            currentSendActionType = Tls11ClientSendAction.ClientHello;
            
            // reset high level protocol stream stack


            while (currentActionType != Tls11ClientActionType.ApplicationDataExchange)
            {
                switch (currentActionType)
                {
                    case Tls11ClientActionType.Wait:
                        WaitActionTransition(); break;
                    case Tls11ClientActionType.Send:
                        SendActionTransition(); break;
                    case Tls11ClientActionType.ApplicationDataExchange:
                        ApplicationDataExchangeTransition();
                        break;
                    default: throw new Exception("Internal error, not possible, only for safety reason.");
                        
                }
            }
        }

        private void ApplicationDataExchangeTransition()
        {
            throw new NotImplementedException();
        }

        private void SendActionTransition()
        {
            switch (currentSendActionType)
            {
                case Tls11ClientSendAction.ClientHello:
                    break;
                case Tls11ClientSendAction.Certificate:
                    break;
                case Tls11ClientSendAction.ClientKeyExchange:
                    break;
                case Tls11ClientSendAction.CertificateVerify:
                    break;
                case Tls11ClientSendAction.ChangeCipherSpec:
                    break;
                case Tls11ClientSendAction.Finished:
                    break;
                default:
                    break;
            }
        }

        private void WaitActionTransition()
        {
            switch (currentWaitActionType)
            {
                case Tls11ClientWaitAction.Certificate:
                    break;
                case Tls11ClientWaitAction.ClientKeyExchange:
                    break;
                case Tls11ClientWaitAction.CertificateVerify:
                    break;
                case Tls11ClientWaitAction.ChangeCipherSpec:
                    break;
                case Tls11ClientWaitAction.Finished:
                    break;
                default:
                    break;
            }
        }

        private void DoNextAction()
        {

        }
    }
}
