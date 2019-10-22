
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class MainTest {

    @Test
    public void encryptData() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, UnrecoverableKeyException, CMSException {
        Security.addProvider(new BouncyCastleProvider());
        CertificateFactory certFactory = CertificateFactory
                .getInstance("X.509", "BC");
        X509Certificate certificate = (X509Certificate) certFactory
                .generateCertificate(new FileInputStream("src/main/resources/public.cer"));
        char[] keystorePassword = "password".toCharArray();
        char[] keyPassword = "password".toCharArray();
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(new FileInputStream("src/main/resources/private.p12"), keystorePassword);
        PrivateKey privateKey = (PrivateKey) keystore.getKey("baeldung", keyPassword);

        byte[] test = "test string 1234567".getBytes();
        byte[] encrypted = Main.encryptData(test, certificate);
        byte[] decryprted = Main.decryptData(encrypted, privateKey);

        Assert.assertArrayEquals(test, decryprted);
    }

    @Test
    public void verifySignedData() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        CertificateFactory certFactory = CertificateFactory
                .getInstance("X.509", "BC");
        X509Certificate certificate = (X509Certificate) certFactory
                .generateCertificate(new FileInputStream("src/main/resources/public.cer"));
        char[] keystorePassword = "password".toCharArray();
        char[] keyPassword = "password".toCharArray();
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(new FileInputStream("src/main/resources/private.p12"), keystorePassword);
        PrivateKey privateKey = (PrivateKey) keystore.getKey("baeldung", keyPassword);

        byte[] test = "test string 1234567".getBytes();
        byte[] signed = Main.signData(test, certificate, privateKey);
        boolean isSigned = Main.verifySignedData(signed);
        Assert.assertTrue(isSigned);
    }
}