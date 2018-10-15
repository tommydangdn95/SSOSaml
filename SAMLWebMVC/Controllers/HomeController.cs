using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Web;
using System.Web.Mvc;
using System.Xml;

namespace SAMLWebMVC.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            XmlDocument doc = new XmlDocument();
            var xmlPath = @"E:\Sample\SAMLWebMVC\SAMLWebMVC\test.xml";
            doc.Load(xmlPath);

            string pfxPath = @"E:\Sample\SAMLWebMVC\SAMLWebMVC\wso2carbon.pfx";
            X509Certificate2 cert = new X509Certificate2(System.IO.File.ReadAllBytes(pfxPath), "wso2carbon");
            SignXmlDocumentWithCertificate(doc, cert);
            string readXml = doc.OuterXml;
            System.IO.File.WriteAllText(@"E:\Sample\SAMLWebMVC\SAMLWebMVC\signed.xml", doc.OuterXml);

            // convert xml to array to convert base 64
            byte[] data = CompressArray(doc);

            // convert to base64
            string enCodeBase64 = Convert.ToBase64String(data);


            return View();
        }

        public byte[] CompressArray(XmlDocument doc)
        {
            MemoryStream ms = new MemoryStream();
            doc.Save(ms);
            byte[] bytes = ms.ToArray();
            return bytes;
        }

        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public void SignXmlDocumentWithCertificate(XmlDocument doc, X509Certificate2 cert)
        {
            SignedXml signedXml = new SignedXml(doc);
            signedXml.SigningKey = cert.PrivateKey;
            Reference reference = new Reference();
            reference.Uri = "";
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            signedXml.AddReference(reference);

            KeyInfo keyinfo = new KeyInfo();
            keyinfo.AddClause(new KeyInfoX509Data(cert));

            signedXml.KeyInfo = keyinfo;
            signedXml.ComputeSignature();
            XmlElement xmlSlg = signedXml.GetXml();

            doc.DocumentElement.AppendChild(doc.ImportNode(xmlSlg, true));
        }

        public string GetXmlContent(string xmlPath)
        {
            var xmlContent = System.IO.File.ReadAllText(xmlPath);
            return xmlContent;
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
    }
}