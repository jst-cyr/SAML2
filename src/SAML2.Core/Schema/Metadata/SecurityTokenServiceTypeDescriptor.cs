using System;
using System.Xml.Serialization;

namespace SAML2.Schema.Metadata
{
    [Serializable]
    [XmlType(Namespace = "http://docs.oasis-open.org/wsfed/federation/200706", TypeName = "SecurityTokenServiceType")]
    [XmlRoot(ElementName, Namespace = Saml20Constants.Metadata, IsNullable = false)]
    public class SecurityTokenServiceTypeDescriptor : RoleDescriptor
    { }
}