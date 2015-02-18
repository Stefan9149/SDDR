package server;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Iterator;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Connection implements Runnable{
	private Socket client;
	private ConcurrentHashMap<String, Document> listOfDoc; 
	private ConcurrentHashMap<String, Connection> connectedClients;
	private String clientName;
	private InputStream inputStream;
	private OutputStream outputStream;
	private Key sharedKey;
	private static String jksPath;
	private static char[] pwd;
	private static String myalias;
	private static IvParameterSpec IV;
	
	Connection(Socket client, ConcurrentHashMap<String, Document> listOfDoc, ConcurrentHashMap<String, Connection> connectedClients) {
		this.client = client;
		this.listOfDoc = listOfDoc;
		this.connectedClients = connectedClients;	
		jksPath = SocketServer.getJksPath();
		pwd = SocketServer.getPwd();
		myalias = SocketServer.getMyalias();
		IV = SocketServer.getIV();
	}
	
	public void run() {
		try {		
			//set up communication I/O stream
			inputStream = client.getInputStream();
			outputStream = client.getOutputStream();
			
			//Receive client name + Key Exchange
			checkAuth(inputStream, outputStream);
			
			while(client.isConnected()) {
				String request = null;
				//parse request from client
				try {
					request = new String(receiveIn(inputStream));
				}catch (IOException ioe) {
					continue;
		        }
				String[] strRequest = (request.split(" "));
				String requestType = strRequest[0];
				System.out.println("[" + clientName + "]\n" + "Request from client: " + new String(request));			
				//EXIT request
				if (requestType.equals("EXIT")) {
					break;
				}
				//PUT request
				else if (requestType.equals("PUT")) {
					String requestUID = strRequest[1];
					String securityFlag = strRequest[2];
					clientPUT(requestUID, securityFlag);
			    }
				//GET request
				else if (requestType.equals("GET")) {
					String requestUID = strRequest[1];
					clientGET(requestUID);
				}						
				//SHOWCLIENT request
				else if (requestType.equals("SHOWCLIENTS")) {
					clientSHOW();
				}
				//DELEGATE request
				else if (requestType.equals("DELEGATE")) {
					String requestUID = strRequest[1];
					String targetName = strRequest[2];
					String expireTime = strRequest[3];
					String rights = strRequest[4];
					String propagation = strRequest[5];
					clientDELEGATE(requestUID, targetName, expireTime, rights, propagation);
				}
				System.out.println("Waiting for further request...\n");
				//show files existed on server
				showFileList();
				backupFileInfo();
			}
			//session end
			System.out.println("Client [" + clientName + "] is disconnected");
		} catch (IOException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	//backup file/client info locally by server
	private void backupFileInfo() throws IOException {
		if(!listOfDoc.isEmpty()) {
			//clean
			//update current info
			File f = new File("backup/listOfDoc.txt");
			FileOutputStream fos = new FileOutputStream(f);
			OutputStreamWriter osw = new OutputStreamWriter(fos);
			Iterator<Entry<String, Document>> it = listOfDoc.entrySet().iterator();
			while (it.hasNext()) {
				Entry<String, Document> item = it.next();
				osw.write(item.getValue().writeInfo() + "\n");
			}		
			osw.close();
			fos.close();
		}
	}
	
	private void showFileList() {
		System.out.println("Files on Server:");
		if(listOfDoc.isEmpty()) {
			System.out.println("No File on Server now...\n");
		}
		for(Document doc: listOfDoc.values()) {
			doc.showFileInfo();
		}
	}

	private void clientSHOW() throws Exception {		
		System.out.println("Showing existed clients...");
		String clientList = new String();
		for(String nameOfClient: connectedClients.keySet()) {
			clientList += nameOfClient + " ";
		}
		sendOut(clientList, outputStream);
	}

	private void clientGET(String requestUID) throws Exception {
		//Firstly respond with agree/deny, then if agree, send file to clients
		//File content will be extracted depending on new/stored security flag
		System.out.println(requestUID); //show request file UID
		//No such file
		if(!listOfDoc.containsKey(requestUID)) { 
			System.out.println("No such File...");
			sendOut("Deny:No such File", outputStream);
		}
		//file exist
		else {			
			//check delegation expiration
			removeExpiredDelegation(listOfDoc.get(requestUID));
			System.out.println("File exists...Checking authorization...");
			Document curDoc = listOfDoc.get(requestUID);
			//if file owner
			if(clientName.equals(curDoc.getOwner())) {
				System.out.println("File owner, check file...");
				sendFileDependOnFlag(requestUID);				
			}
			//if delegated
			else if(curDoc.delegationRecord.containsKey(clientName)) {
				if(!curDoc.delegationRecord.get(clientName).isExpired()) {
					if(curDoc.delegationRecord.get(clientName).canRead()) {
						System.out.println("Delegated, check file...");
						sendFileDependOnFlag(requestUID);	
					}
					//Have delegated credential, but requested right is not supported
					else {
						sendOut("Deny:No such right in delegation", outputStream);
						System.out.println("No such right in delegation...");
					}
				}
				//no use now, since delegations will be checked before every new behavior to the file
				else {
					sendOut("Deny:Delegation Expired", outputStream);
					//remove expired delegation
					curDoc.removeDelegation(curDoc.delegationRecord.get(clientName).getUser());
					System.out.println("Delegation Expired...");
				}	
			}
			//if delegated to ALL
			else if(curDoc.delegationRecord.containsKey("ALL")) {
				if(!curDoc.delegationRecord.get("ALL").isExpired()) {
					if(curDoc.delegationRecord.get("ALL").canRead()) {
						System.out.println("Delegated, check file...");
						sendFileDependOnFlag(requestUID);	
					}
					//Have delegated credential, but requested right is not supported
					else {
						sendOut("Deny:No such right in delegation", outputStream);
						System.out.println("No such right in delegation...");
					}
				}
				//no use now, since delegations will be checked before every new behavior to the file
				else {
					sendOut("Deny:Delegation Expired", outputStream);
					//remove expired delegation
					curDoc.removeDelegation(curDoc.delegationRecord.get("ALL").getUser());
					System.out.println("Delegation Expired...");
				}	
			}
			//Not authorized client
			else { 
				System.out.println("Client is not authorized to do so...");
			    sendOut("Deny:Neither owner nor delegated", outputStream);
			}
		}
	}
	
	private void clientPUT(String requestUID, String securityFlag) throws Exception {	
		//Firstly respond with agree/deny, then if agree, save/update file
		//File content will be save depending on new/stored security flag
		System.out.println("Checking authorization for the client...");
		System.out.println(requestUID);
		//new file
		if(!listOfDoc.containsKey(requestUID)) { 
			System.out.println("It is a new File");
			agreeOrDeny(true);
			updateFileInfo(requestUID, securityFlag, updateFile(requestUID, securityFlag), "new");
		}
		//file exists
		else {
			//check delegation expiration
			removeExpiredDelegation(listOfDoc.get(requestUID));
			System.out.println("File exists...Checking authorization...");
			Document curDoc = listOfDoc.get(requestUID);
			//if file owner
			if(clientName.equals(curDoc.getOwner())) {
				System.out.println("File owner, overwrite file...");
				agreeOrDeny(true);
				updateFileInfo(requestUID, securityFlag, updateFile(requestUID, securityFlag), "exist");
			}
			//if delegated
			else if(curDoc.delegationRecord.containsKey(clientName)) {
				if(!curDoc.delegationRecord.get(clientName).isExpired()) {
					if(curDoc.delegationRecord.get(clientName).canWrite()) {
						sendOut("Agree:but you cannot change the security flag", outputStream);
						updateFileInfo(requestUID, listOfDoc.get(requestUID).getSecurityFlag(), updateFile(requestUID, listOfDoc.get(requestUID).getSecurityFlag()), "exist");
					}
					//Have delegated credential, but requested right is not supported
					else {
						sendOut("Deny:No such right in delegation", outputStream);
						System.out.println("No such right in delegation...");
					}
				}
				else {
					//No use now, expired delegation will be checked every time PUT/GET/DELEGATION by delegated client
					sendOut("Deny:Delegation Expired", outputStream);
					//remove expired delegation
					curDoc.removeDelegation(curDoc.delegationRecord.get(clientName).getUser());
					System.out.println("Delegation Expired...");
				}	
			}
			//if delegated to ALL
			else if(curDoc.delegationRecord.containsKey("ALL")) {
				if(!curDoc.delegationRecord.get("ALL").isExpired()) {
					if(curDoc.delegationRecord.get("ALL").canWrite()) {
						sendOut("Agree:but you cannot change the security flag", outputStream);
						updateFileInfo(requestUID, listOfDoc.get(requestUID).getSecurityFlag(), updateFile(requestUID, listOfDoc.get(requestUID).getSecurityFlag()), "exist");
					}
					//Have delegated credential, but requested right is not supported
					else {
						sendOut("Deny:No such right in delegation", outputStream);
						System.out.println("No such right in delegation...");
					}
				}
				else {
					//No use now, expired delegation will be checked every time PUT/GET/DELEGATION by delegated client
					sendOut("Deny:Delegation Expired", outputStream);
					//remove expired delegation
					curDoc.removeDelegation(curDoc.delegationRecord.get("ALL").getUser());
					System.out.println("Delegation Expired...");
				}	
			}
			//Not authorized
			else { 
				System.out.println("Client is not authorized to do so...");
			    sendOut("Deny:Neither owner nor delegated", outputStream);
			}
			
		}
	}
		
	private void clientDELEGATE(String requestUID, String targetName, String expireTime, String rights, String propagation) throws Exception {
		//Respond with agree/deny
		//Delegated rights will saved with document information
		//No such file
		if(!listOfDoc.containsKey(requestUID)) { 
			System.out.println("No such file");
			sendOut("Deny:No such file", outputStream);
		}
		//file exists
		else {
			removeExpiredDelegation(listOfDoc.get(requestUID));
			System.out.println("File exists...Checking authorization...");
			Document curDoc = listOfDoc.get(requestUID);
			//if file owner
			if(clientName.equals(curDoc.getOwner())) {
				System.out.println("File owner, is able to delegate...\n");
				//further check
				delegateTry(targetName, expireTime, rights, propagation, curDoc, false);
			}
			//if delegated
			else if(curDoc.delegationRecord.containsKey(clientName)) {
				if(!curDoc.delegationRecord.get(clientName).isExpired()) {
					if(curDoc.delegationRecord.get(clientName).canPropagate()) {
						System.out.println("Delegated the right to propagate");
						sendOut("Agree:You have right to propagate, but cannot expand the time and rights, want continue? (Y/N)", outputStream);
						String choice = new String(receiveIn(inputStream));
						if(choice.equals("Y")){
							//further check
							delegateTry(targetName, expireTime, rights, propagation, curDoc, true);
						}
						//if choose 'N'...
						else {
							System.out.println("Not enough delegated right...");
							sendOut("Deny:Not enough delegated right...", outputStream);
						}
					}
					//have delegation, cannot propagate
					else {
						sendOut("Deny:Not support propagation in delegation", outputStream);
						System.out.println("No propagate right in delegation...");
					}
				}
				//no use anymore, will be check before this.
				else {
					sendOut("Deny:Delegation Expired", outputStream);
					//remove expired delegation
					curDoc.removeDelegation(curDoc.delegationRecord.get(clientName).getUser());
					System.out.println("Delegation Expired...");
				}	
			}
			//if delegated to ALL
			else if(curDoc.delegationRecord.containsKey("ALL")) {
				if(!curDoc.delegationRecord.get("ALL").isExpired()) {
					if(curDoc.delegationRecord.get("ALL").canPropagate()) {
						System.out.println("Delegated the right to propagate");
						sendOut("Agree:You have right to propagate, but cannot expand the time and rights, want continue? (Y/N)", outputStream);
						String choice = new String(receiveIn(inputStream));
						if(choice.equals("Y")){
							//further check
							delegateTry(targetName, expireTime, rights, propagation, curDoc, true);
						}
						//if choose 'N'...
						else {
							System.out.println("Not enough delegated right...");
							sendOut("Deny:Not enough delegated right...", outputStream);
						}
					}
					//have delegation, cannot propagate
					else {
						sendOut("Deny:Not support propagation in delegation", outputStream);
						System.out.println("No propagate right in delegation...");
					}
				}
				//no use anymore, will be check before this.
				else {
					sendOut("Deny:Delegation Expired", outputStream);
					//remove expired delegation
					curDoc.removeDelegation(curDoc.delegationRecord.get("ALL").getUser());
					System.out.println("Delegation Expired...");
				}	
			}
			//Not authorized
			else { 
				System.out.println("Client is not authorized to do so...");
			    sendOut("Deny:Neither owner nor delegated", outputStream);
			}
		}	
	}

	private void delegateTry(String targetName, String expireTime, String rights, String propagation, Document curDoc, boolean isDelegated)
			throws Exception {
		if(!connectedClients.containsKey(targetName) && !targetName.equals("ALL")) {
			//no such client
			System.out.println("The delegated client is not registered to server...");
			sendOut("Deny:This client is not exist", outputStream);
		}
		else {
			//if agree			
			agreeOrDeny(true);
			System.out.println("Added the access of delegated file for delegated client.");
			//Add the delegated right into "ACL"(a parameter of document class, specifically for delegation)
			//delegated
			if(isDelegated) {
				//created time not change , so expire time no need to change
				Date createdTime = curDoc.delegationRecord.get(clientName).getCreatedTime();
				long t = curDoc.delegationRecord.get(clientName).getExpireTime();
				boolean propa = curDoc.delegationRecord.get(clientName).canPropagate();
				String r = curDoc.delegationRecord.get(clientName).getRights();
				Delegation newDele = new Delegation(targetName, createdTime, t, r, propa);
				curDoc.addDelegation(targetName, newDele);
			}
			//owner
			else {
				//set new delegation, overwrite former one
				long time = Long.parseLong(expireTime);
				boolean propa;
				if(propagation.equals("TRUE")) {
					propa = true;
				}
				else {
					propa = false;
				}
				Delegation newDele = new Delegation(targetName, time, rights, propa);
				curDoc.addDelegation(targetName, newDele);
			}
		}
	}
	
	private void agreeOrDeny(boolean decision) throws Exception {
		//basic response
		if(decision) {
			sendOut("Agree", outputStream);
		} 
		else {
			sendOut("Deny", outputStream);
		}
	}
	
	private byte[] receiveIn(InputStream in) throws Exception {
		DataInputStream dIn = new DataInputStream(in);
		int length = dIn.readInt();                    
		byte[] temp=null;
		if(length>0) {
			temp = new byte[length];
		    dIn.readFully(temp, 0, temp.length); 
		}
		//decryption with shared key
		return decrypt(temp);
	}
	
	private byte[] receiveInFirstTime(InputStream in) throws IOException {
		DataInputStream dIn = new DataInputStream(in);
		int length = dIn.readInt();                    
		byte[] temp=null;
		if(length>0) {
			temp = new byte[length];
		    dIn.readFully(temp, 0, temp.length); 
		}
		//for the first hand shake
		return temp;
	}
	
	private void sendOut(String temp, OutputStream out) throws Exception {
		byte[] buffer = temp.getBytes();
		//Encrypted with SharedKey
		byte[] cipher = encrypt(buffer);
		DataOutputStream dOut = new DataOutputStream(out);
        dOut.writeInt(cipher.length); 
        dOut.write(cipher);
	}
	
	private byte[] updateFile(String UID, String SecurityFlag) throws Exception {
		System.out.println("updateFile...");
		//return encypted doc key/signature
		return saveFile(UID, SecurityFlag);
	}

	private byte[] saveFile(String UID, String SecurityFlag) throws Exception {
		byte[] fileContent = receiveIn(inputStream);
		//keep encypted doc key or signature
		byte[] result = null;
		//store flag with doc
		if(SecurityFlag.equals("CONFIDENTIALITY")) {
			//generate a key for file encryption
			Key key = gensecretKey();
			//encrypt document key with server's public key, store with file
			result = storeFileKey(key);
			//encrypt file with document key
			encryptFile(fileContent, UID, key);
		}
		else if(SecurityFlag.equals("INTEGRITY")) {
			saveFileNormal(UID, fileContent);
			//compute and save signature
			result = signFile(fileContent);
		}
		else if(SecurityFlag.equals("NONE")) {
			saveFileNormal(UID, fileContent);
		}
		
		return result;
	}

	private void updateFileInfo(String requestUID,  String securityFlag, byte[] securityRecord, String type) throws IOException {
		DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
		//current time
		Date date = new Date();
		String now = dateFormat.format(date).toString();
		//get file handler
		File file = new File(requestUID);
		//new file
		if(type.equals("new")) {
			//create a new doc
			Document newDoc = new Document();
			//set details
			newDoc.setUID(requestUID);
			newDoc.setOwner(clientName);
			newDoc.setFileLength(file.length());
			newDoc.setCreatedTime(now);//Keep created time, change last modified
			newDoc.setLastModified(now);
			//Delegate define securityflag
			newDoc.setSecurityFlag(securityFlag);
			newDoc.setSecurityKeyOrSignature(securityRecord);	
			//put into doc list
			listOfDoc.put(requestUID, newDoc);
		}
		//file exist
		else {
			Document doc = listOfDoc.get(requestUID);
				doc.setFileLength(file.length());
				doc.setLastModified(now);
				doc.setSecurityFlag(securityFlag);
				doc.setSecurityKeyOrSignature(securityRecord);
			removeExpiredDelegation(doc);

		}	
	}

	private void saveFileNormal(String UID, byte[] fileContent)
			throws FileNotFoundException, IOException {
		//normally save file
		if(fileContent.length>0){
			BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(UID));
			bos.write(fileContent,0,fileContent.length);
			bos.close();
		}else{
			System.out.println("empty file");
		}
	}	

	private void sendFileDependOnFlag(String UID) throws Exception {
		//check security flag
		if(listOfDoc.get(UID).getSecurityFlag().equals("CONFIDENTIALITY")) {
			//for CONFIDENTIALITY, need to decrypt stored encrypted document key(with server key)
			//Then use the document key to decrypt file content.
			agreeOrDeny(true);
			byte[] fileContent=null;
			//restore/decrypt the document key
			Key restoredKey = restoreFileKey(listOfDoc.get(UID).getSecurityKeyOrSignature());
			//decrypt the document content
			fileContent = decryptFile(UID, restoredKey);
			sendOut(new String(fileContent), outputStream);
			System.out.println("Sent file...");
		}
		else if(listOfDoc.get(UID).getSecurityFlag().equals("INTEGRITY")) {
			//for INTEGRITY, need to check if file content is consistent with the stored signature
			//If correct, send file, or not send file but warning of file changes.
			File send = new File(UID);
			FileInputStream fis = new FileInputStream(UID);
			byte[] fileContent = new byte[(int) send.length()];
			fis.read(fileContent);
			fis.close();
			//check signature
			boolean ver = verifySignedFile(fileContent,listOfDoc.get(UID).getSecurityKeyOrSignature());
			if(ver){
				agreeOrDeny(true);
				sendFileNormal(UID);
				System.out.println("Sent file...");
			}
			else{
				sendOut("Deny:The file changed unexpected", outputStream);
				System.out.println("The file modified...not send to client");
			}
		}
		else if(listOfDoc.get(UID).getSecurityFlag().equals("NONE")){
			//if NONE, just send file normally
			agreeOrDeny(true);
			sendFileNormal(UID);
			System.out.println("Sent file...");
		}
	}
	
	private void sendFileNormal(String UID) throws Exception {	
		File send = new File(UID);
		byte[] fileContent = new byte[(int) send.length()];
		BufferedInputStream bis = new BufferedInputStream(new FileInputStream(send));
		bis.read(fileContent, 0, fileContent.length);
		bis.close();
		sendOut(new String(fileContent), outputStream);
	}
	
	
	private void checkAuth(InputStream inputStream, OutputStream outputStream) throws Exception {
		byte[] loginName = receiveInFirstTime(inputStream);
		clientName = new String(loginName);
		//record as connected client
		connectedClients.put(clientName, this);
		System.out.println("[" + clientName + "]\n" + "Username:" + clientName);
		
		//Secure Channel
		chaServer channel = new chaServer(client, pwd, myalias, jksPath);
		sharedKey = channel.startChannel();	
		//System.out.println(sharedKey.toString());
		
		//if agree
		System.out.println("Authorized user, waiting for request...");
		showFileList();
		agreeOrDeny(true);
	}
	
	private void removeExpiredDelegation(Document doc) throws IOException {
		//clean delegation backup
		PrintWriter writer = new PrintWriter("backup/delegation/" + doc.getUID().split(".txt")[0] + "_delegation.txt");
		writer.close();
		//remove expired delegation
		if(!doc.delegationRecord.isEmpty()) {
			Iterator<Entry<String, Delegation>> it = doc.delegationRecord.entrySet().iterator();
			while (it.hasNext()) {
				Entry<String, Delegation> item = it.next();
				if(item.getValue().isExpired()) {
					//remove expired delegation from record
					doc.removeDelegation(item.getKey());
					//update local backup file
					File f = new File( "backup/delegation/" + doc.getUID().split(".txt")[0] + "_delegation.txt");
					FileOutputStream fos = new FileOutputStream(f);
					OutputStreamWriter osw = new OutputStreamWriter(fos);
					Iterator<Entry<String, Delegation>> it2 = doc.delegationRecord.entrySet().iterator();
					while (it2.hasNext()) {
						Entry<String, Delegation> item2 = it2.next();
						osw.write(item2.getValue().writeInfo() + "\n");
					}		
					osw.close();
					fos.close();
				}
			}
		}
	}
	
	public boolean isConnected() {
		return client.isConnected();
	}
	
	public byte[] encrypt(byte[] input) throws Exception {
		encryptChannel eChannel = new encryptChannel();
		return eChannel.encrypt(input, sharedKey);
	}
	
	public byte[] decrypt(byte[] input) throws Exception {
		encryptChannel eChannel = new encryptChannel();
		return eChannel.decrypt(input, sharedKey);
	}
	
	//generate a key to encrypte user file	
		public static Key gensecretKey() throws Exception{
		KeyGenerator kg = KeyGenerator.getInstance("AES");
		kg.init(256,new SecureRandom());
		Key key = kg.generateKey();
		return key;
		}
	//encrypt above key
		public static byte[] storeFileKey(Key key)throws Exception{
			KeyStore ks = KeyStore.getInstance("JKS");
			String caalias = "ca";
			FileInputStream fis= new FileInputStream(jksPath);
			getKeystore gks= new getKeystore(ks,pwd, fis, myalias,caalias);
			PublicKey myPublicKey = gks.getCer(ks, myalias).getPublicKey();
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, myPublicKey);
			byte[] encrypted = cipher.doFinal(key.getEncoded());
			return encrypted;
		}
	//decrypte that key
		public static Key restoreFileKey(byte[]encrypted)throws Exception{
			KeyStore ks = KeyStore.getInstance("JKS");
			String caalias = "ca";
			FileInputStream fis= new FileInputStream(jksPath);
			getKeystore gks= new getKeystore(ks,pwd, fis, myalias,caalias);
			PrivateKey myPrivateKey = gks.getPrivateKey(ks,myalias,pwd);
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.DECRYPT_MODE, myPrivateKey);
			byte[] decrypted = cipher.doFinal(encrypted);
			Key originalKey = new SecretKeySpec(decrypted, 0, decrypted.length, "AES");
			return originalKey;
			
		}
	//encrypt the file   
		public static void encryptFile(byte[] plainText, String UID, Key key) throws Exception {
			

			Cipher encryptCipher = null;

			encryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

			encryptCipher.init(Cipher.ENCRYPT_MODE, key, IV);

			byte[] encrypted = null;

			encrypted = encryptCipher.doFinal(plainText);
			File testFile = new File(UID);
			
			FileOutputStream fos = new FileOutputStream(testFile);
			fos.write(encrypted);
			fos.close();
		}
	//decrypte the file
		public static byte[] decryptFile(String filename,Key key)throws Exception{
		File testFile = new File(filename);
		
		FileInputStream fis = new FileInputStream(testFile);
		
		int size = (int) testFile.length();
		byte[] file =new byte[size];
		fis.read(file);
			Cipher decryptCipher = null;

			decryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

			decryptCipher.init(Cipher.DECRYPT_MODE, key, IV);

			byte[] decrypted = null;

			decrypted = decryptCipher.doFinal(file);
	//System.out.println(new String(decrypted));
			fis.close();
			return decrypted;

		}
	//sign the file with server private key
	public static byte[] signFile(byte[] fileText)throws Exception{
		KeyStore ks = KeyStore.getInstance("JKS");
		String caalias = "ca";
		FileInputStream fis= new FileInputStream(jksPath);
		getKeystore gks= new getKeystore(ks,pwd, fis, myalias,caalias);
		PrivateKey myPrivateKey = gks.getPrivateKey(ks,myalias,pwd);
		Signature rsa = Signature.getInstance("SHA1withRSA");
		rsa.initSign(myPrivateKey);
		rsa.update(fileText);
		byte[] fileSign = rsa.sign();
		fis.close();
		return fileSign;
		
	}
	//verify the signature with server public key
	public static boolean verifySignedFile(byte[] fileText,byte[] fileSign)throws Exception{
		KeyStore ks = KeyStore.getInstance("JKS");
		String caalias = "ca";
		FileInputStream fis= new FileInputStream(jksPath);
		getKeystore gks= new getKeystore(ks,pwd, fis, myalias,caalias);
		PublicKey myPublicKey = gks.getCer(ks, myalias).getPublicKey();
		
		Signature rsa = Signature.getInstance("SHA1withRSA");
	    rsa.initVerify(myPublicKey);
		rsa.update(fileText);
		boolean verified = rsa.verify(fileSign);
		fis.close();
		return verified;
	}
	
}

