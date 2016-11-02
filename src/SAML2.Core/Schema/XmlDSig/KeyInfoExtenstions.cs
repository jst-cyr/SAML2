using System;
using System.Xml;
using SAML2.Utils;

namespace SAML2.Schema.XmlDSig
{
    internal static class KeyInfoExtenstions
    {
        public static System.Security.Cryptography.Xml.KeyInfoClause ToKeyInfoClause<T>(this object ki) where T : System.Security.Cryptography.Xml.KeyInfoClause, new()
        {
            var result = new T();
            var doc = new XmlDocument();

            doc.LoadXml(Serialization.SerializeToXmlString(ki, new [] { ki.GetType(), typeof(System.Security.Cryptography.Xml.KeyInfoClause), typeof(T) }));
            if (doc.DocumentElement != null)
            {
                result.LoadXml(doc.DocumentElement);
            }

            return result;
        }
    }
}