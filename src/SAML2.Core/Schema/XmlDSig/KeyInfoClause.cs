using System.Security.Cryptography.Xml;
using System.Xml;
using SAML2.Utils;

namespace SAML2.Schema.XmlDSig
{
    public class KeyInfoClause<T> where T : System.Security.Cryptography.Xml.KeyInfoClause, new()
    {
        public virtual T GetKeyInfoClause()
        {
            var result = new T();
            var doc = new XmlDocument();

            doc.LoadXml(Serialization.SerializeToXmlString(this, new[] { GetType(), typeof(System.Security.Cryptography.Xml.KeyInfoClause), typeof(T) }));
            if (doc.DocumentElement != null)
            {
                result.LoadXml(doc.DocumentElement);
            }

            return result;
        }
    }
}