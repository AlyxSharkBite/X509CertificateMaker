using System;
using System.IO;
using System.Linq;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace X509CertificateMaker
{
    public static class X509Creator
    {
        /// <summary>
        /// Creates a X509Certificate2 with Private Key in DER Format
        /// </summary>
        /// <param name="certName">Name for Certificate</param>
        /// <param name="keyLength">Desired Rsa Key Length in Bits (512 - 15360)</param>
        /// <param name="password">Certificate password</param>
        /// <returns>Encrypted DER Encoded X509Certificate2</returns>
        /// <example>
        /// <code>
        /// var x509Der = X509CertificateMaker.X509Creator.GenerateX509Certificate("myCert", 2048, "Abc123");
        /// X509Certificate2 certificate = new X509Certificate2(x509Der, "Abc123");       
        /// </code>
        /// </example>
        public static byte[] GenerateX509Certificate(string certName, int keyLength, string password)
        {
            // Validate Key Length
            if (!Enumerable.Range(512, 15360).Contains(keyLength))
                throw new ArgumentOutOfRangeException($"Keysize must be between 512 and 15360");

            // Setup            
            var secureRandom = new SecureRandom(new CryptoApiRandomGenerator());
            var keyGenerationParameters = new KeyGenerationParameters(secureRandom, keyLength);

            // Create the Key Pair
            var rsaKeyPairGenerator = new RsaKeyPairGenerator();
            rsaKeyPairGenerator.Init(keyGenerationParameters);
            var keypair = rsaKeyPairGenerator.GenerateKeyPair();

            // Create the Cert Generator             
            var certificateGenerator = new X509V3CertificateGenerator();

            // Create the Signature Factory
            ISignatureFactory signatureFactory = new Asn1SignatureFactory("SHA256WithRSAEncryption", keypair.Private, secureRandom);

            // Create the Cert Parameters
            var x509Name = new X509Name("CN=" + certName);
            var serialNumber = BigInteger.ProbablePrime(120, secureRandom);

            // Add the Cert Information
            certificateGenerator.SetSerialNumber(serialNumber);
            certificateGenerator.SetSubjectDN(x509Name);
            certificateGenerator.SetIssuerDN(x509Name);
            certificateGenerator.SetNotAfter(DateTime.MaxValue);
            certificateGenerator.SetNotBefore(DateTime.Today);
            certificateGenerator.SetPublicKey(keypair.Public);

            // Generate the Cert w/o the private key
            var x509Cert = certificateGenerator.Generate(signatureFactory);

            // Add Privte Key and get back in DER format. 
            return CreatePkcs12Data(x509Cert, keypair.Private, password);            
        }

        private static byte[] CreatePkcs12Data(X509Certificate certificate, AsymmetricKeyParameter privateKey, string password)
        {
            // Create certificate entry
            var certEntry = new X509CertificateEntry(certificate);
            var friendlyName = certificate.SubjectDN.ToString();

            // Create the Store
            var builder = new Pkcs12StoreBuilder();
            builder.SetUseDerEncoding(true);
            var store = builder.Build();

            // Create store entry
            store.SetKeyEntry(friendlyName,
                new AsymmetricKeyEntry(privateKey),
                new[]
                {
                    certEntry
                });

            // Save the Cert
            using (var pkcs12Stream = new MemoryStream())
            {
                store.Save(pkcs12Stream, password.ToCharArray(), new SecureRandom(new CryptoApiRandomGenerator()));
                return Pkcs12Utilities.ConvertToDefiniteLength(pkcs12Stream.ToArray(), password.ToCharArray());
            }

        }
    }
}
