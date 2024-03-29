import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.*;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class Main {

    public static void main(String[] args) {
//        Security.addProvider(new BouncyCastleProvider());
//        CertificateFactory certFactory = CertificateFactory
//                .getInstance("X.509", "BC");
//        X509Certificate certificate = (X509Certificate) certFactory
//                .generateCertificate(new FileInputStream("src/main/resources/public.cer"));
//        char[] keystorePassword = "password".toCharArray();
//        char[] keyPassword = "password".toCharArray();
//        KeyStore keystore = KeyStore.getInstance("PKCS12");
//        keystore.load(new FileInputStream("src/main/resources/private.p12"), keystorePassword);
//        PrivateKey privateKey = (PrivateKey) keystore.getKey("baeldung",
//                keyPassword);
//
//        String secretMessage = "My password is 123456Seven";
//        System.out.println("Original Message : " + secretMessage);
//        byte[] stringToEncrypt = secretMessage.getBytes();
//        byte[] encryptedData = encryptData(stringToEncrypt, certificate);
//        System.out.println("Encrypted Message : " + new String(encryptedData));
//        byte[] rawData = decryptData(encryptedData, privateKey);
//        String decryptedMessage = new String(rawData);
//        System.out.println("Decrypted Message : " + decryptedMessage);
//
//        byte[] signedData = signData("My password is 123456Seven".getBytes(), certificate, privateKey);
//        Boolean check = verifySignedData(signedData);
//        System.out.println(check);
    }

    public static byte[] encryptData(byte[] data, X509Certificate encryptionCertificate)
            throws CertificateEncodingException, CMSException, IOException {
        byte[] encryptedData = null;
        if (null != data && null != encryptionCertificate) {
            CMSEnvelopedDataGenerator cmsEnvelopedDataGenerator
                    = new CMSEnvelopedDataGenerator();
            JceKeyTransRecipientInfoGenerator jceKey
                    = new JceKeyTransRecipientInfoGenerator(encryptionCertificate);
            cmsEnvelopedDataGenerator.addRecipientInfoGenerator(jceKey);
            CMSTypedData msg = new CMSProcessableByteArray(data);
            OutputEncryptor encryptor
                    = new JceCMSContentEncryptorBuilder(CMSAlgorithm.CAMELLIA128_CBC)
                    .setProvider("BC").build();
            CMSEnvelopedData cmsEnvelopedData = cmsEnvelopedDataGenerator
                    .generate(msg, encryptor);
            encryptedData = cmsEnvelopedData.getEncoded();
        }
        return encryptedData;
    }

    public static byte[] decryptData(byte[] encryptedData, PrivateKey decryptionKey) throws CMSException {
        byte[] decryptedData = null;
        if (null != encryptedData && null != decryptionKey) {
            CMSEnvelopedData envelopedData = new CMSEnvelopedData(encryptedData);
            Collection<RecipientInformation> recipients
                    = envelopedData.getRecipientInfos().getRecipients();
            KeyTransRecipientInformation recipientInfo
                    = (KeyTransRecipientInformation) recipients.iterator().next();
            JceKeyTransRecipient recipient
                    = new JceKeyTransEnvelopedRecipient(decryptionKey);
            return recipientInfo.getContent(recipient);
        }
        return decryptedData;
    }

    public static byte[] signData(byte[] data, X509Certificate signingCertificate, PrivateKey signingKey) throws Exception {
        byte[] signedMessage;
        List<X509Certificate> certList = new ArrayList<>();
        CMSTypedData cmsData = new CMSProcessableByteArray(data);
        certList.add(signingCertificate);
        Store certs = new JcaCertStore(certList);
        CMSSignedDataGenerator cmsGenerator = new CMSSignedDataGenerator();
        ContentSigner contentSigner
                = new JcaContentSignerBuilder("SHA256withRSA").build(signingKey);
        cmsGenerator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().setProvider("BC")
                        .build()).build(contentSigner, signingCertificate));
        cmsGenerator.addCertificates(certs);
        CMSSignedData cms = cmsGenerator.generate(cmsData, true);
        signedMessage = cms.getEncoded();
        return signedMessage;
    }

    public static boolean verifySignedData(byte[] signedData) throws Exception {
        ByteArrayInputStream inputStream
                = new ByteArrayInputStream(signedData);
        ASN1InputStream asnInputStream = new ASN1InputStream(inputStream);
        CMSSignedData cmsSignedData = new CMSSignedData(
                ContentInfo.getInstance(asnInputStream.readObject()));
        SignerInformationStore signers
                = cmsSignedData.getSignerInfos();
        SignerInformation signer = signers.getSigners().iterator().next();
        Collection certCollection
                = cmsSignedData.getCertificates().getMatches(signer.getSID());
        X509CertificateHolder certHolder = (X509CertificateHolder) certCollection.iterator().next();
        return signer.verify(new JcaSimpleSignerInfoVerifierBuilder()
                .build(certHolder));
    }
}
