package client;
import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.OutputStream;
import java.net.Socket;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;


public class chaClient {
 	private Socket s;
    private char [] pwd;
    private String myalias;
    private String jksPath;
    private KeyStore ks;
    private String caalias;
    private FileInputStream fis;
	private getKeystore gks;
	private Certificate clientCertificate;
	private PrivateKey myPrivateKey;
	private PublicKey caPublicKey;
	
    chaClient(Socket s, char[] pwd, String myalias, String jksPath) throws Exception{
    	this.s = s;
		this.pwd = pwd;
		this.myalias = myalias;
		this.jksPath = jksPath;
		//Connect KeyStore, Get Cert
		ks = KeyStore.getInstance("JKS");
    	caalias = "ca";	 
        fis = new FileInputStream(jksPath);       
        gks = new getKeystore(ks,pwd,fis,myalias,caalias);      
        clientCertificate = gks.getCer(ks,myalias);
        myPrivateKey = gks.getPrivateKey(ks,myalias, pwd);
        caPublicKey = gks.getTrustedPkey(ks,caalias);
	}
	
	public Key startChannel()throws Exception{
        //Exchange Certificate
        sendCertificate(s,clientCertificate);
        Certificate serverCertificate = getCertificate(s,caPublicKey);
        //Key Exchange
		byte[] getServerGen = getServerGen(s, myPrivateKey);
        byte[] generatedRandNum = genPartOne(s, serverCertificate);
		String serverRand = new String(getServerGen);
		String clientRand = new String(generatedRandNum);
		StringBuffer buffer = new StringBuffer(serverRand);
		buffer.append(clientRand);
		byte[] combine = buffer.toString().getBytes();
		MessageDigest md = MessageDigest.getInstance("SHA1");
		byte[] sharedKey = md.digest(combine);
		SecretKeySpec key = new SecretKeySpec(sharedKey, 0, 16, "AES");
		return key;

	}
	
	public static byte[] genPartOne(Socket s, Certificate serverCertificate) throws Exception {
        //Generate a random number, 100 bytes
		Random random = new Random();
		byte[] bytes = new byte[100];
		random.nextBytes(bytes);	
		//Encrypt
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, serverCertificate);
		byte[] encrypted = cipher.doFinal(bytes);
		//Send to server
        DataOutputStream dOut = new DataOutputStream(s.getOutputStream());
        dOut.writeInt(encrypted.length); 
        dOut.write(encrypted);
        return bytes;
	}
	
	
	
    public Certificate getCertificate(Socket s, PublicKey tpkey)throws Exception{
        BufferedInputStream input = new BufferedInputStream(s.getInputStream());
        java.security.cert.Certificate serverCert = CertificateFactory.getInstance("X.509").generateCertificate(input);
   //     System.out.println(serverCert.toString());
        
        serverCert.verify(tpkey);
        PublicKey serverPubkey = serverCert.getPublicKey();
   //     System.out.println("server public key is"+serverPubkey.toString());
        return serverCert;
        
	}

    public void sendCertificate(Socket s, Certificate clientCertificate)throws Exception{  
	OutputStream output = s.getOutputStream();
        byte[] frame = clientCertificate.getEncoded();
        output.write(frame);
        output.flush();
    }   
       
    public static byte[] getServerGen(Socket s,PrivateKey myPrivateKey) throws Exception{
		//receive encrypted random number from server
    	DataInputStream dIn = new DataInputStream(s.getInputStream());
		int length = dIn.readInt();                    
		byte[] cipherText=null;
		if(length>0) {
		    cipherText = new byte[length];
		    dIn.readFully(cipherText, 0, cipherText.length); 
		}
		//Decrypt
		Cipher dcipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		dcipher.init(Cipher.DECRYPT_MODE, myPrivateKey);
		byte[] decrypted = dcipher.doFinal(cipherText);
		return decrypted;
    }     
}






