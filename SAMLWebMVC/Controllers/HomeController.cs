using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
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
            var xmlPath = @"E:\Sample\SAMLWebMVC\SAMLWebMVC\test.xml";
            var xmlContent = GetXmlContent(xmlPath);

            // convert xml to array to convert base 64 SAmlRequest
            byte[] dataRequest = CompressArray(xmlContent);
            // base64
            string samlRequestBase64 = Convert.ToBase64String(dataRequest);

            // encode URl
            string samlRequestEncode = Server.UrlEncode(samlRequestBase64);

            // encode RelayStat
            string relayStatEncode = Server.UrlEncode("http://localhost:2825/Home/About");

            // encode sigAlEncode
            string sigAlgEncode = Server.UrlEncode("http://www.w3.org/2000/09/xmldsig#rsa-sha1");

            // chuoi can ky
            string urlToBeSign = "SAMLRequest=" + samlRequestEncode + "&RelayState=" + relayStatEncode + "&SigAlg=" + sigAlgEncode;

            // sign string
            var signString = Sign(urlToBeSign);

            string samlAuthRequest = "https://192.168.1.116:9443/samlsso?" + urlToBeSign + "&Signature=" + Server.UrlEncode(signString);

            ViewBag.SamlAuthRequest = samlAuthRequest;
            return View();
        }

        public byte[] CompressArray(string xmlContent)
        {
            using (MemoryStream inMemStream = new MemoryStream(Encoding.ASCII.GetBytes(xmlContent)), outMemStream = new MemoryStream())
            {
                // create a compression stream with the output stream
                using (var zipStream = new DeflateStream(outMemStream, CompressionMode.Compress, true))
                    // copy the source string into the compression stream
                    inMemStream.WriteTo(zipStream);

                // return the compressed bytes in the output stream
                return outMemStream.ToArray();
            }
        }

        public ActionResult About(string response="")
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public string SignXmlDocumentWithCertificate(string strToBeSign, X509Certificate2 cert)
        {
            var privateKey = cert.PrivateKey as RSACryptoServiceProvider;

            var stream = new MemoryStream();
            var writer = new StreamWriter(stream);
            writer.Write(strToBeSign);
            writer.Flush();
            stream.Position = 0;

            var signature = privateKey.SignData(stream, "SHA1");

            return Convert.ToBase64String(signature);
        }

        public string GetXmlContent(string xmlPath)
        {
            var xmlContent = System.IO.File.ReadAllText(xmlPath);
            return xmlContent;
        }


        public string Sign(string strToBeSign)
        {
            var path = @"E:\Sample\SAMLWebMVC\SAMLWebMVC\wso2carbon.pfx";
            var password = "wso2carbon";

            var collection = new X509Certificate2Collection();

            collection.Import(path, password, X509KeyStorageFlags.PersistKeySet);

            var certificate = collection[0];

            var privateKey = certificate.PrivateKey as RSACryptoServiceProvider;

            var stream = new MemoryStream();
            var writer = new StreamWriter(stream);
            writer.Write(strToBeSign);
            writer.Flush();
            stream.Position = 0;

            var signature = privateKey.SignData(stream, "SHA1");

            return Convert.ToBase64String(signature);
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
    }
}