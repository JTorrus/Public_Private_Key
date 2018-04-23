using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MessageEncryptedNS
{
    /// <summary>
    /// Aquesta classe permet guardar tota la informació necessària a enviar entre un emissor i receptor
    /// per a missatges encriptats utilitzant la tècnica de la clau pública i privada. 
    /// </summary>
    [Serializable]
    public class MessageEncryptedClass
    {
        //Hash del missatge per a la seva comprovació d'integritat
        public byte[] SignedHash { get; set; }

        //Missatge encriptat en clau simètrica
        public byte[] EncryptedMsg { get; set; }

        //Clau simètrica encriptada (amb la clau pública del receptor)
        public byte[] EncryptedKey { get; set; }

        //IV encriptat (amb la clau pública del receptor)
        public byte[] EncryptedIV { get; set; }
    }
}
