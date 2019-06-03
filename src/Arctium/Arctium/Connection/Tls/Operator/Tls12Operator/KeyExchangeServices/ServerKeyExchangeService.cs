using System;
using Arctium.Connection.Tls.CryptoConfiguration;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions;
using Arctium.Connection.Tls.Protocol;
using System.Security.Cryptography;
using Arctium.Connection.Tls.Configuration;
using System.Security.Cryptography.X509Certificates;
using Arctium.Connection.Tls.Protocol.BinaryOps.FixedOps;
using System.Xml;
using System.Numerics;
using Arctium.Connection.Tls.Buffers;
using Arctium.Connection.Tls.Protocol.BinaryOps;
using System.Globalization;

namespace Arctium.Connection.Tls.Operator.Tls12Operator.KeyExchangeServices
{
    class ServerKeyExchangeService
    {
        static readonly NamedCurve[] SupportedNamedCurves = new NamedCurve[] { NamedCurve.Secp256r1, NamedCurve.Secp384r1, NamedCurve.Secp521r1 };

        Context context;
        Tls12ServerConfig config;
        ECDiffieHellmanCng ecDiffineHellman;
        string xmlECDHPublicKey;

        KeyExchangeAlgorithm selectedKeyExchangeAlgorithm { get { return CryptoSuites.Get(context.allHandshakeMessages.ServerHello.CipherSuite).KeyExchangeAlgorithm; } }

        public ServerKeyExchangeService(Context context, Tls12ServerConfig config)
        {
            this.context = context;
            this.config = config;
        }

        public bool CanExchangeKeysOnAlgorithm(KeyExchangeAlgorithm algorithm, ClientHello clientHello)
        {
            if (algorithm == KeyExchangeAlgorithm.RSA) return true;
            else if (algorithm == KeyExchangeAlgorithm.ECDHE)
            {
                return CheckIfCanExchangeOnECDHE(clientHello);
            }
            else return false;
        }

        public bool NeedToSendKeyExchange()
        {
            if (selectedKeyExchangeAlgorithm == KeyExchangeAlgorithm.RSA) return false;
            else if (selectedKeyExchangeAlgorithm == KeyExchangeAlgorithm.ECDHE) return true;
            else throw new Exception("INTERNAL_ServerKeyExchangeService:: not supporetd algorithm (?)"); // for safety reasons
        }

        public ServerKeyExchange CreateNewKeyExchangeMessage()
        {
            if (selectedKeyExchangeAlgorithm == KeyExchangeAlgorithm.RSA) throw new Exception("INTERNAL_ServerKeyExchangeService, this message is not supported in RSA mode");//for safety reasons
            else if (selectedKeyExchangeAlgorithm == KeyExchangeAlgorithm.ECDHE)
            {
                return CreateECDHMessage();
            }
            else throw new Exception("INTERNA::Not supported serverkeyexchange");
        }

        void ToHex(string s, out byte[] x, out byte[] y)
        {
            x = new byte[32];
            y = new byte[32];
            
            for (int i = 0; i < 32; i++)
            {
                x[i] = byte.Parse(s[i * 2].ToString() + s[(2*i) + 1].ToString(), System.Globalization.NumberStyles.HexNumber);
            }
            for (int i = 32; i < 64; i++)
            {
                y[i - 32] = byte.Parse(s[(2 * i)].ToString() + s[(2*i) + 1].ToString(), System.Globalization.NumberStyles.HexNumber);
            }
        }

        private ServerKeyExchange CreateECDHMessage()
        {
            NamedCurve selectedCurve = SelectClientNamedCurve();
            HashAlgorithmType hashAlgo; SignatureAlgorithm signAlgo;

            SelectSignatureAlgorithms(out hashAlgo, out signAlgo);

            ServerKeyExchange serverKeyExchange = new ServerKeyExchange();

            if (signAlgo != SignatureAlgorithm.RSA) throw new Exception("internal");

            RSA signRSA = config.Certificates[0].GetRSAPrivateKey();

            

            byte[] x, y;
            GetCoordFromXmlECDHEPublicKey(out x, out y);
            //string coordString = "2401f19090fb73d7c39e6d20cf40fcef2d813d6dabed37883ed3f804a6c6cd55b6c9db15863ccfce2945724e764542e61f45e967029f222cf183a69beb5c934f";
            //ToHex(coordString, out x, out y);



            //
            //
            //

            byte[] paramsBytes = FixedKeyExchangeFormatter.FormatECDHParamsOnNamedCurve(x, y, selectedCurve);

            //byte[] signature = config.Certificates[0].GetRSAPrivateKey().SignData(paramsBytes, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);

            RSAPKCS1SignatureFormatter rsaformatter = new RSAPKCS1SignatureFormatter(config.Certificates[0].GetRSAPrivateKey());

            rsaformatter.SetHashAlgorithm("SHA1");

            byte[] toHash = BufferTools.Join(context.allHandshakeMessages.ClientHello.Random,
                context.allHandshakeMessages.ServerHello.Random,
                paramsBytes);

            byte[] signature = rsaformatter.CreateSignature((SHA1.Create().ComputeHash(toHash)));

            byte[] hashSignLenPrefix = new byte[4];

            hashSignLenPrefix[0] = 2; //sha1
            hashSignLenPrefix[1] = 1; //rsa

            NumberConverter.FormatUInt16((ushort)signature.Length, hashSignLenPrefix, 2);


            byte[] paramsSignature = BufferTools.Join(hashSignLenPrefix, signature);

            serverKeyExchange.KeyExchangeRawBytes = BufferTools.Join(paramsBytes, paramsSignature);

            return serverKeyExchange;
        }

        private void GetCoordFromXmlECDHEPublicKey(out byte[] x, out byte[] y)
        {
            string xHex;
            string yHex;

            while (true)
            {
                int keySize = 256;
                ECDiffieHellmanCng keyGenerator = new ECDiffieHellmanCng(keySize);

                this.xmlECDHPublicKey = keyGenerator.PublicKey.ToXmlString();

                XmlDocument doc = new XmlDocument();
                doc.LoadXml(xmlECDHPublicKey);

                string xstring = doc.DocumentElement.ChildNodes[1].ChildNodes[0].Attributes[0].Value;
                string ystring = doc.DocumentElement.ChildNodes[1].ChildNodes[1].Attributes[0].Value;

                xHex = BigInteger.Parse(xstring, NumberFormatInfo.InvariantInfo).ToString("X"); ;
                yHex = BigInteger.Parse(ystring, NumberFormatInfo.InvariantInfo).ToString("X") ;
                
                if (xHex.Length == 63) xHex = "0" + xHex;
                if (yHex.Length == 63) yHex = "0" + yHex;


                if (xHex.Length != 64 || yHex.Length != 64) continue;

                ecDiffineHellman = keyGenerator;

                break;
            }


            Console.WriteLine("X "+xHex.Length+":" + xHex);
            Console.WriteLine("Y "+yHex.Length+":" + yHex);

            x = new byte[32];
            y = new byte[32];

            for (int i = 0; i < 32; i++)
            {
                x[i] = byte.Parse(xHex[i * 2].ToString() + xHex[(i * 2) + 1].ToString(), NumberStyles.HexNumber);
                y[i] = byte.Parse(yHex[i * 2].ToString() + yHex[(i * 2) + 1].ToString(), NumberStyles.HexNumber);

            }


            //if (xCoord.Length < lengthInBytes)
            //{
            //    int dif = lengthInBytes - xCoord.Length;
            //    byte[] newx = new byte[dif + xCoord.Length];

            //    Buffer.BlockCopy(xCoord, 0, newx, dif, xCoord.Length);
            //    xCoord = newx;
            //}

            //if (yCoord.Length < lengthInBytes)
            //{
            //    int dif = lengthInBytes - yCoord.Length;
            //    byte[] newy = new byte[dif + yCoord.Length];

            //    Buffer.BlockCopy(yCoord, 0, newy, dif, yCoord.Length);
            //    yCoord = newy;
            //}


            //x = xCoord;
            //y = yCoord;
        }

        private void SelectSignatureAlgorithms(out HashAlgorithmType hashAlgo, out SignatureAlgorithm signatureAlgo)
        {
            hashAlgo = HashAlgorithmType.NULL;
            signatureAlgo = SignatureAlgorithm.RSA;
            SignatureAlgorithmsExtension sigAlgoExt = null;

            foreach (var ext in context.allHandshakeMessages.ClientHello.Extensions)
            {
                if (ext.Type == HandshakeExtensionType.SignatureAlgorithms)
                {
                    sigAlgoExt = (SignatureAlgorithmsExtension)ext;
                    break;
                }
            }

            if (sigAlgoExt == null)
            {
                hashAlgo = HashAlgorithmType.SHA1;
            }
            else
            {
                foreach (var shAlgo in sigAlgoExt.SignatureAndHashAlgorithmList)
                {
                    if (shAlgo.SignatureAlgorithm == SignatureAlgorithm.RSA)
                    {
                        HashAlgorithmType supportedHashByClient = shAlgo.HashAlgorithm;
                        if (supportedHashByClient == HashAlgorithmType.SHA1 ||
                            supportedHashByClient == HashAlgorithmType.SHA256 ||
                            supportedHashByClient == HashAlgorithmType.SHA384 ||
                            supportedHashByClient == HashAlgorithmType.SHA512)
                        {
                            hashAlgo = supportedHashByClient;
                            break;
                        }

                    }
                }
            }


        }

        private NamedCurve SelectClientNamedCurve()
        {
            return NamedCurve.Secp256r1;
            NamedCurve[] clientCurves = GetNamedCurvesSupportedByClient(context.allHandshakeMessages.ClientHello);

            foreach (var serverCurve in SupportedNamedCurves)
            {
                foreach (var clientCurve in clientCurves)
                {
                    if (serverCurve == clientCurve) return serverCurve;
                }
            }

            throw new Exception("internal exception, serverkeyexchange");
        }

        public byte[] GetPremaster()
        {
            if (selectedKeyExchangeAlgorithm == KeyExchangeAlgorithm.RSA)
            {
                RSA rsa = config.Certificates[0].GetRSAPrivateKey();
                byte[] premaster = rsa.Decrypt(context.allHandshakeMessages.ClientKeyExchange.KeyExchangeRawBytes, RSAEncryptionPadding.Pkcs1);

                return premaster;
            }
            else if (selectedKeyExchangeAlgorithm == KeyExchangeAlgorithm.ECDHE)
            {
                return GetPremasterOnECDHE();
            }
            else
            {
                throw new Exception("INTERNAL_ServerKeyExchangeService::not supported key exchange method (?)");
            }
        }

        private byte[] GetPremasterOnECDHE()
        {
            byte[] ecdhKeys = context.allHandshakeMessages.ClientKeyExchange.KeyExchangeRawBytes;

            byte[] xCoord = new byte[32];
            byte[] yCoord = new byte[32];
            Buffer.BlockCopy(ecdhKeys, 2, xCoord, 0, 32);
            Buffer.BlockCopy(ecdhKeys, 2 + 32, yCoord, 0, 32);

            string xStrHex = "", yStrHex = "";

            for (int i = 0; i < 32; i++)
            {
                xStrHex += xCoord[i].ToString("X2"); 
                yStrHex += yCoord[i].ToString("X2");
            }

            xStrHex = "00" + xStrHex;
            yStrHex = "00" + yStrHex;

            BigInteger xbi = BigInteger.Parse(xStrHex, NumberStyles.HexNumber);
            BigInteger ybi = BigInteger.Parse(yStrHex, NumberStyles.HexNumber);

            string xStrDec = xbi.ToString();
            string yStrDec = ybi.ToString();


            XmlDocument doc = new XmlDocument();
            doc.LoadXml(xmlECDHPublicKey);

            string xstring = doc.DocumentElement.ChildNodes[1].ChildNodes[0].Attributes[0].Value = xStrDec;
            string ystring = doc.DocumentElement.ChildNodes[1].ChildNodes[1].Attributes[0].Value = yStrDec;

            string xmlPublicKeyFromClient = doc.OuterXml;




            ECDiffieHellmanCngPublicKey kkkey = ECDiffieHellmanCngPublicKey.FromXmlString(xmlPublicKeyFromClient);

            byte[] result = ecDiffineHellman.DeriveKeyMaterial(kkkey);


            return result;
        }

        private bool CheckIfCanExchangeOnECDHE(ClientHello clientHello)
        {
            NamedCurve[] namedCurvesSupportedByClient = GetNamedCurvesSupportedByClient(clientHello);
            NamedCurve[] namedCurvesSupportedByServer = SupportedNamedCurves;

            if (namedCurvesSupportedByClient == null) return false;

            foreach (NamedCurve byServer in namedCurvesSupportedByServer)
            {
                foreach (NamedCurve byClient in namedCurvesSupportedByClient)
                {
                    if (byServer == byClient) return true;
                }
            }

            return false;
        }

        private NamedCurve[] GetNamedCurvesSupportedByClient(ClientHello clientHello)
        {
            //find named curves extensions (if present)
            foreach (var extension in clientHello.Extensions)
            {
                if (extension.Type == HandshakeExtensionType.EllipticCurves)
                {
                    return ((EllipticCurvesExtension)extension).EllipticCurveList;
                }
            }

            return null;
        }

        private HashAlgorithm GetHashAlgorithm(HashAlgorithmType type)
        {
            switch (type)
            {
                case HashAlgorithmType.MD5: return MD5.Create();
                case HashAlgorithmType.SHA1: return SHA1.Create();
                case HashAlgorithmType.SHA256: return SHA256.Create();
                case HashAlgorithmType.SHA384: return SHA384.Create();
                case HashAlgorithmType.SHA512: return SHA512.Create();
                default: throw new Exception("internal ");
            }
        }

        private int GetNamedCurveLength(NamedCurve namedCurve)
        {
            switch (namedCurve)
            {
                case NamedCurve.Secp256r1: return 256;
                case NamedCurve.Secp384r1: return 384;
                case NamedCurve.Secp521r1: return 521;
                default: throw new Exception("internal error");    
            }
        }
    }
}
