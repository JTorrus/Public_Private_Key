using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Serialization.Formatters.Binary;
using MessageEncryptedNS;
using static SerializeUtils.SerializeUtils;

namespace sender
{

    class Program
    {
        //Atributs de Sockets
        private static IPAddress ServerIP;
        private static int PortIP;
        private static IPEndPoint ServerEndPoint;
        private static NetworkStream ServerNS;

        //Algorisme clau pública - privada
        static RSACryptoServiceProvider RSASender = new RSACryptoServiceProvider();
        static RSACryptoServiceProvider RSAReceiver = new RSACryptoServiceProvider();
        
        //Permet guardar informació de claus asimètriques
        static RSAParameters PublicKeyRecipient;
        static RSAParameters ReceivedPublicKey;

        //Custom object per guardar tota la informació del missatge
        static MessageEncryptedClass MsgEncrypted = new MessageEncryptedClass();

        static void Main(string[] args)
        {

            ConnectServer();

            string msg;
            Console.WriteLine("Escriu el missatge a enviar:");
            msg = Console.ReadLine();

            //Intercanvi de claus públiques amb el client
            RepClauPublica();
            EnviarClauPublica();

            //Xifra el missatge utilitzant la tècnica de clau pública i privada
            XifrarMissatge(msg);
            EnviarMissatgeEncriptat();

            Console.ReadLine();
        }

        /// <summary>
        /// Es connecta al servidor i actualitzar la variable de classe ServerNS (Networkstream)
        /// </summary>
        static void ConnectServer()
        {
            PortIP = 11000;
            IPAddress[] ips;

            ips = Dns.GetHostAddresses("127.0.0.1");
            ServerIP = ips[0];
            ServerEndPoint = new IPEndPoint(ServerIP, PortIP);

            TcpListener Server = new TcpListener(ServerEndPoint);

            Server.Start();
            TcpClient Client = Server.AcceptTcpClient();
            ServerNS = Client.GetStream();
        }

        /// <summary>
        /// Rebem la clau pública del client i la guardem a la varialbe PublicKeyRecipient
        /// </summary>
        static void RepClauPublica()
        {
            //1. Read del Socket
            byte[] receivedBuffer = new byte[256];
            int receivedBytes = ServerNS.Read(receivedBuffer, 0, receivedBuffer.Length);

            //2. Deserialitzem sobre la variable PublicKeyRecipient
            ReceivedPublicKey = (RSAParameters)Deserialize(receivedBuffer);
        }

        //Enviam la clau pública del servidor al client
        static void EnviarClauPublica()
        {
            //1. Serialitzem la clau pública de l'emissor
            RSAParameters PublicKeySender = RSASender.ExportParameters(false);
            byte[] PublicKeyBytes = Serialize(PublicKeySender);

            //2. Enviem (write sobre Socket) la clau pública al receptor
            ServerNS.Write(PublicKeyBytes, 0, PublicKeyBytes.Length);
        }

        //Xifrem el missatge
        static void XifrarMissatge(string msg)
        {
            //1. Signatura del missatge
            
            // TESTS
            /*string PrivateKeyString = RSASender.ToXmlString(true);
            RSASender.FromXmlString(PrivateKeyString);

            RSAPKCS1SignatureFormatter RSAFormatter = new RSAPKCS1SignatureFormatter(RSASender);
            RSAFormatter.SetHashAlgorithm("SHA1");

            SHA1Managed HashSHA1 = new SHA1Managed();
            byte[] SignedHashValue = RSAFormatter.CreateSignature(HashSHA1.ComputeHash(new UnicodeEncoding().GetBytes(msg)));*/

            byte[] MsgToBytes = Encoding.UTF8.GetBytes(msg);
            MsgEncrypted.SignedHash = RSASender.SignData(MsgToBytes, new SHA1CryptoServiceProvider());

            //2. Encriptació missatge 
            AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
            aes.GenerateIV();
            aes.GenerateKey();

            var cryptor = aes.CreateEncryptor();
            byte[] MsgEncryptedBytes = cryptor.TransformFinalBlock(MsgToBytes, 0, MsgToBytes.Length);

            MsgEncrypted.EncryptedMsg = MsgEncryptedBytes;

            //3. Encriptació de la clau 
            RSAReceiver.ImportParameters(ReceivedPublicKey);

            MsgEncrypted.EncryptedIV = RSAReceiver.Encrypt(aes.IV, true);
            MsgEncrypted.EncryptedKey = RSAReceiver.Encrypt(aes.Key, true);

            Console.WriteLine("SignedHash: {0}", BytesToStringHex(MsgEncrypted.SignedHash));
            Console.WriteLine("Encrypted Message: {0}", BytesToStringHex(MsgEncrypted.EncryptedMsg));
            Console.WriteLine("Encrypted Key: {0}", BytesToStringHex(MsgEncrypted.EncryptedKey));
            Console.WriteLine("Encrypted IV: {0}", BytesToStringHex(MsgEncrypted.EncryptedIV));
        }

        /// <summary>
        /// Mètode que enviarà al receptat a través del Socket el missatge encriptat, 
        /// és a dir la variable MsgEncrypted
        /// </summary>
        public static void EnviarMissatgeEncriptat()
        {
            byte[] SerializedMsg = Serialize(MsgEncrypted);

            ServerNS.Write(SerializedMsg, 0, SerializedMsg.Length);
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

