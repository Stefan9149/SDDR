package server;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.TrustedCertificateEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;

//import java.security.Certificate;
import sun.misc.BASE64Encoder;

public class getKeystore {

	KeyStore ks = null;
	char[] pwd = null;
	FileInputStream fis = null;
	String myalias = null;
	String caalias = null;

	getKeystore(KeyStore ks, char[] pwd, FileInputStream fis, String myalias,
			String caalias) throws Exception {

		this.pwd = pwd;
		this.fis = fis;
		this.myalias = myalias;
		this.caalias = caalias;
		ks.load(fis, pwd);

	}

	public PrivateKey getPrivateKey(KeyStore ks, String alias, char[] pwd)
			throws NoSuchAlgorithmException, UnrecoverableEntryException,
			KeyStoreException {
		BASE64Encoder myB64 = new BASE64Encoder();

		KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(
				pwd);

		PrivateKeyEntry pkEntry = (PrivateKeyEntry) ks.getEntry(alias,
				protParam);
		PrivateKey myPrivateKey = pkEntry.getPrivateKey();
		String privateKey = myB64.encode(myPrivateKey.getEncoded());

		return myPrivateKey;
	}

	public Certificate getCer(KeyStore ks, String alias)
			throws KeyStoreException {
		Certificate Cer = ks.getCertificate(alias);

		return Cer;
	}

	public PublicKey getTrustedPkey(KeyStore ks, String alias)
			throws NoSuchAlgorithmException, UnrecoverableEntryException,
			KeyStoreException {
		TrustedCertificateEntry tce = (TrustedCertificateEntry) ks.getEntry(
				alias, null);

		Certificate tCert = tce.getTrustedCertificate();
		PublicKey tPKey = tCert.getPublicKey();
		// System.out.println("ca's public key is "+ tPKey.toString());
		return tPKey;

	}

	public PublicKey getPublic(Certificate cer) {
		PublicKey publicKey = cer.getPublicKey();
		return publicKey;

	}

}
