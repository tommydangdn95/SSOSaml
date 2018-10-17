using Microsoft.IdentityModel.Tokens.Saml2;
using Newtonsoft.Json;
using Sustainsys.Saml2.Saml2P;
using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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

        public ActionResult About(string SAMLResponse)
        {
            //string samlCertificate = @"-----BEGIN CERTIFICATE-----MIIDSTCCAjGgAwIBAgIEAoLQ/TANBgkqhkiG9w0BAQsFADBVMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExFjAUBgNVBAcTDU1vdW50YWluIFZpZXcxDTALBgNVBAoTBFdTTzIxEjAQBgNVBAMTCWxvY2FsaG9zdDAeFw0xNzA3MTkwNjUyNTFaFw0yNzA3MTcwNjUyNTFaMFUxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzENMAsGA1UEChMEV1NPMjESMBAGA1UEAxMJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAluZFdW1ynitztkWLC6xKegbRWxky+5P0p4ShYEOkHs30QI2VCuR6Qo4Bz5rTgLBrky03W1GAVrZxuvKRGj9V9+PmjdGtau4CTXu9pLLcqnruaczoSdvBYA3lS9a7zgFU0+s6kMl2EhB+rk7gXluEep7lIOenzfl2f6IoTKa2fVgVd3YKiSGsyL4tztS70vmmX121qm0sTJdKWP4HxXyqK9neolXI9fYyHOYILVNZ69z/73OOVhkh/mvTmWZLM7GM6sApmyLX6OXUp8z0pkY+vT/9+zRxxQs7GurC4/C1nK3rI/0ySUgGEafO1atNjYmlFN+M3tZX6nEcA6g94IavyQIDAQABoyEwHzAdBgNVHQ4EFgQUtS8kIYxQ8UVvVrZSdgyide9OHxUwDQYJKoZIhvcNAQELBQADggEBABfk5mqsVUrpFCYTZZhOxTRRpGXqoW1G05bOxHxs42Paxw8rAJ06Pty9jqM1CgRPpqvZa2lPQBQqZrHkdDE06q4NG0DqMH8NT+tNkXBe9YTre3EJCSfsvswtLVDZ7GDvTHKojJjQvdVCzRj6XH5Truwefb4BJz9APtnlyJIvjHk1hdozqyOniVZd0QOxLAbcdt946chNdQvCm6aUOputp8Xogr0KBnEy3U8es2cAfNZaEkPU8Va5bU6Xjny8zGQnXCXxPKp7sMpgO93nPBt/liX1qfyXM7xEotWoxmm6HZx8oWQ8U5aiXjZ5RKDWCCq4ZuXl6wVsUz1iE61suO5yWi8=-----END CERTIFICATE-----";
            //Response samlResponse = new Response(samlCertificate);
            //samlResponse.LoadXmlFromBase64(Request.Form["SAMLResponse"]);


            string rawSamlData = Request["SAMLResponse"];

            // the sample data sent us may be already encoded, 
            // which results in double encoding
            if (rawSamlData.Contains('%'))
            {
                rawSamlData = HttpUtility.UrlDecode(rawSamlData);
            }

            // read the base64 encoded bytes
            byte[] samlData = Convert.FromBase64String(rawSamlData);

            // read back into a UTF string
            string samlAssertion = Encoding.UTF8.GetString(samlData);
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(samlAssertion);
            string json = JsonConvert.SerializeXmlNode(doc);
            Saml2Id idsamlpe = new Saml2Id("iicipgbjllfjifdjjglpmancpfijenlmpfkbjdeb");
            var readSamlp = Saml2Response.Read(samlAssertion, idsamlpe);

            ViewBag.JsonExtract = json;
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

            X509Certificate2 cert = new X509Certificate2(System.IO.File.ReadAllBytes(path), "wso2carbon");
            var a = cert.PrivateKey.ToXmlString(false);

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