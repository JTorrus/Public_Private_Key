using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SerializeUtils
{
    public class SerializeUtils
    {
        public static byte[] Serialize(object objectToSerialize)
        {
            BinaryFormatter BinFormatter = new BinaryFormatter();
            MemoryStream MemStream = new MemoryStream();

            BinFormatter.Serialize(MemStream, objectToSerialize);
            byte[] bytesToSend = MemStream.ToArray();

            MemStream.Close();

            return bytesToSend;
        }

        public static object Deserialize(byte[] bytesToDeserialize)
        {
            BinaryFormatter BinFormatter = new BinaryFormatter();
            MemoryStream MemStream = new MemoryStream();

            MemStream.Write(bytesToDeserialize, 0, bytesToDeserialize.Length);
            MemStream.Seek(0, SeekOrigin.Begin);

            object DeserializedObject = BinFormatter.Deserialize(MemStream);
            MemStream.Close();

            return DeserializedObject;
        }
    }
}
