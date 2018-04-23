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
        static MessageEncryptedClass MsgEncrypted = new MessageEncryptedClass();
        static RSAParameters PublicKey;

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
        }

		//Rep la clau pública de l'emissor
        static void RepClauPublica()
        {

        }

		//Rep el missatge encriptat
        static void ReceiveEncryptedMessage()
        {
        }

		//Desxifra el missatge
        static void DesxifrarMissatge()
        {            

			//1. Desencripta la clau simètrica (key + IV)


			//2. Desencriptem el missatge


            //3. Comprovació de la integritat.  

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
