
# X509CertificateMaker
X509 Certificate Creation 
* Leverages BouncyCastle under the hood. 

Simple Library for creating Self Signed X509 Certificates with RSA Privake Key. 
This project arose from a need to create a bunch of certs for some local apps.

## Use

    var x509Der = X509CertificateMaker.X509Creator.GenerateX509Certificate("myCert", 2048, "Abc123");
    X509Certificate2 certificate = new X509Certificate2(x509Der, "Abc123");   

    
