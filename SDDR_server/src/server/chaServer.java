package server;
import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class chaServer {
	
	private Socket s = null;
	private char[] pwd = null;
	private String myalias = null;
	private String jksPath = null;

	chaServer(Socket s, char[] pwd, String myalias, String jksPath) {
		this.s = s;
		this.pwd = pwd;
		this.myalias = myalias;
		this.jksPath = jksPath;
	}

	public Key startChannel() throws Exception {
		//Connect to KeyStore
		KeyStore ks = KeyStore.getInstance("JKS");
		String caalias = "ca";
		FileInputStream fis = null;
		fis = new FileInputStream(jksPath);
		getKeystore gks = new getKeystore(ks, pwd, fis, myalias, caalias);
		//Get Cert
		Certificate serverCertificate = gks.getCer(ks, myalias);
		//PublicKey myPublicKey = gks.getPublic(serverCertificate);
		PrivateKey myPrivateKey = gks.getPrivateKey(ks, myalias, pwd);
		PublicKey caPublicKey = gks.getTrustedPkey(ks, caalias);
		//Exchange Certificate
		sendCertificate(s, serverCertificate);
		Certificate clientCertificate = getCertificate(s, caPublicKey);
		//Key Exchange
		byte[] generatedRandNum = genPartOne(s, clientCertificate);
		byte[] getClientGen = getClientGen(s, myPrivateKey);
		String serverRand = new String(generatedRandNum);
		String clientRand = new String(getClientGen);
		StringBuffer buffer = new StringBuffer(serverRand);
		buffer.append(clientRand);
		byte[] combine = buffer.toString().getBytes();
		MessageDigest md = MessageDigest.getInstance("SHA1");
		byte[] sharedKey = md.digest(combine);
		SecretKeySpec key = new SecretKeySpec(sharedKey, 0, 16, "AES");
		return key;
	}
	
	public static byte[] genPartOne(Socket s, Certificate clientCertificate) throws Exception {
        Random random = new Random();
		byte[] bytes = new byte[100];
		random.nextBytes(bytes);	
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, clientCertificate);
		byte[] encrypted = cipher.doFinal(bytes);	
        DataOutputStream dOut = new DataOutputStream(s.getOutputStream());
        dOut.writeInt(encrypted.length); 
        dOut.write(encrypted);
        return bytes;
	}
	public Certificate getCertificate(Socket s, PublicKey tpkey)
			throws Exception {
		BufferedInputStream input = new BufferedInputStream(s.getInputStream());
		java.security.cert.Certificate clientCert = CertificateFactory
				.getInstance("X.509").generateCertificate(input);
		clientCert.verify(tpkey);
		return clientCert;

	}

	public void sendCertificate(Socket s, Certificate serverCertificate)
			throws Exception {
		OutputStream output = s.getOutputStream();
		byte[] frame = serverCertificate.getEncoded();
		output.write(frame);
		output.flush();
	}

	public byte[] getClientGen(Socket s, PrivateKey myPrivateKey)
			throws Exception {
		DataInputStream dIn = new DataInputStream(s.getInputStream());
		int length = dIn.readInt();                    // read length of incoming message
		byte[] cipherText=null;
		if(length>0) {
		    cipherText = new byte[length];
		    dIn.readFully(cipherText, 0, cipherText.length); // read the message
		}

		Cipher dcipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		dcipher.init(Cipher.DECRYPT_MODE, myPrivateKey);
		byte[] decrypted = dcipher.doFinal(cipherText);
		return decrypted;
	}
	

}