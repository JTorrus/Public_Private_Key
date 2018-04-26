using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Xml.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using MessageEncryptedNS;
using static SerializeUtils.SerializeUtils;

namespace recipient
{
    class Program
    {
        //Atributs de Sockets
        private static IPAddress ServerIP;
        private static int PortIP;
        private static IPEndPoint ServerEndPoint;
        private static NetworkStream ClientNS;

        //Criptografia
        static RSACryptoServiceProvider RSARecipient = new RSACryptoServiceProvider();
        static RSACryptoServiceProvider RSAReceived = new RSACryptoServiceProvider();
        static MessageEncryptedClass MsgEncrypted = new MessageEncryptedClass();
        static MessageEncryptedClass ReceivedMsgEncrypted = new MessageEncryptedClass();
        static RSAParameters PublicKey;
        static RSAParameters ReceivedPublicKey;

        //Missatge final desencriptat
        static string StrDecryptedMsg;

        static void Main(string[] args)
        {
			ConnectToServer();
			
            EnviarClauPublica();
            RepClauPublica();

            ReceiveEncryptedMessage();
            DesxifrarMissatge();

            Console.ReadLine();     
        }

		//Connecta amb el servidor i actualitzar la variable ClientNS
		static void ConnectToServer()
		{
            PortIP = 11000;
            ServerIP = IPAddress.Parse("127.0.0.1");
            ServerEndPoint = new IPEndPoint(ServerIP, PortIP);

            TcpClient Client = new TcpClient();

            Client.Connect(ServerEndPoint);
            ClientNS = Client.GetStream();

		}
		
		//Envia la clau pública a l'emissor
        static void EnviarClauPublica()
        {
            PublicKey = RSARecipient.ExportParameters(false);
            byte[] PublicKeyBytes = Serialize(PublicKey);

            ClientNS.Write(PublicKeyBytes, 0, PublicKeyBytes.Length);
        }

		//Rep la clau pública de l'emissor
        static void RepClauPublica()
        {
            byte[] ReceivedBuffer = new byte[2046];
            int ReceivedBytes = ClientNS.Read(ReceivedBuffer, 0, ReceivedBuffer.Length);

            ReceivedPublicKey = (RSAParameters)Deserialize(ReceivedBuffer);
        }

		//Rep el missatge encriptat
        static void ReceiveEncryptedMessage()
        {
            byte[] ReceivedBuffer = new byte[2046];
            int ReceivedBytes = ClientNS.Read(ReceivedBuffer, 0, ReceivedBuffer.Length);

            ReceivedMsgEncrypted = (MessageEncryptedClass)Deserialize(ReceivedBuffer);
        }

		//Desxifra el missatge
        static void DesxifrarMissatge()
        {
            RSAReceived.ImportParameters(ReceivedPublicKey);

            //1. Desencripta la clau simètrica (key + IV)
            byte[] DecryptedIVBytes = RSARecipient.Decrypt(ReceivedMsgEncrypted.EncryptedIV, true);
            byte[] DecryptedKeyBytes = RSARecipient.Decrypt(ReceivedMsgEncrypted.EncryptedKey, true);

            //2. Desencriptem el missatge
            AesCryptoServiceProvider Aes = new AesCryptoServiceProvider();
            Aes.IV = DecryptedIVBytes;
            Aes.Key = DecryptedKeyBytes;

            var Decryptor = Aes.CreateDecryptor();
            byte[] MsgDecryptedBytes = Decryptor.TransformFinalBlock(ReceivedMsgEncrypted.EncryptedMsg, 0, ReceivedMsgEncrypted.EncryptedMsg.Length);

            //3. Comprovació de la integritat.
            if (RSAReceived.VerifyData(MsgDecryptedBytes, new SHA1CryptoServiceProvider(), ReceivedMsgEncrypted.SignedHash))
            {
                StrDecryptedMsg = Encoding.UTF8.GetString(MsgDecryptedBytes);

                Console.WriteLine("Incoming message: {0}", StrDecryptedMsg);
            }
            else
            {
                Console.WriteLine("DECRYPT ERROR");
            }
            
        }

        static string BytesToStringHex(byte[] result)
        {
            StringBuilder stringBuilder = new StringBuilder();

            foreach (byte b in result)
                stringBuilder.AppendFormat("{0:x2}", b);

            return stringBuilder.ToString();
        }
    }
}
