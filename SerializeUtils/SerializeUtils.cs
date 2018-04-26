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
            BinaryFormatter binaryFormatter = new BinaryFormatter();
            MemoryStream memoryStream = new MemoryStream();

            binaryFormatter.Serialize(memoryStream, objectToSerialize);
            byte[] bytesToSend = memoryStream.ToArray();

            memoryStream.Close();

            return bytesToSend;
        }

        public static object Deserialize(byte[] bytesToDeserialize)
        {
            BinaryFormatter binaryFormatter = new BinaryFormatter();
            MemoryStream memoryStream = new MemoryStream();

            memoryStream.Write(bytesToDeserialize, 0, bytesToDeserialize.Length);
            memoryStream.Seek(0, SeekOrigin.Begin);

            object DeserializedObject = binaryFormatter.Deserialize(memoryStream);
            memoryStream.Close();

            return DeserializedObject;
        }
    }
}
