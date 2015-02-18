package server;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.util.Iterator;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;


public class Document {
	private String UID;
	private String Owner;
	private long fileLength;
	private String CreatedTime;
	private String LastModified;
	public ConcurrentHashMap<String, Delegation> delegationRecord;
	//return encypted doc key/signature
	private byte[] securityKeyOrSignature;
	private String securityFlag;
	
	Document() {
		delegationRecord = new ConcurrentHashMap<String, Delegation>();
		securityKeyOrSignature = null;
	}
	
	Document(String record) throws IOException {
		delegationRecord = new ConcurrentHashMap<String, Delegation>();
		securityKeyOrSignature = null;
		String[] temp = record.split(";");
		UID = temp[0];
		Owner = temp[1];
		fileLength = Long.valueOf(temp[2]);
		CreatedTime = temp[3];
		LastModified = temp[4];
		String delegationFile = temp[5];
		if(!delegationFile.equals("NULL")){
			File f = new File( "backup/delegation/" + UID.split(".txt")[0] + "_delegation.txt");
			BufferedReader br = new BufferedReader(new FileReader(f));
			String line;
			while ((line = br.readLine()) != null) {
				Delegation d = new Delegation(line);
				addDelegation(d.getUser(), d);
			}
			br.close();
		}
		String payloadFile = temp[6];
		if(!payloadFile.equals("NULL")){
			File f = new File( "backup/payload/" + UID.split(".txt")[0] + "_payload.txt");
			byte[] fileContent = new byte[(int) f.length()];
			BufferedInputStream bis = new BufferedInputStream(new FileInputStream(f));
			bis.read(fileContent, 0, fileContent.length);
			securityKeyOrSignature = fileContent;
			bis.close();
		}
		securityFlag = temp[7];		
	}
	
	public String writeInfo() throws IOException {
		String length = new String(String.valueOf(fileLength));
		String delegationFile=null; 
		String securityPayloadFile;
		if(!delegationRecord.isEmpty()) {
			//save delegation in specific file
			//clean
				File f = new File( "backup/delegation/" + UID.split(".txt")[0] + "_delegation.txt");
				FileOutputStream fos = new FileOutputStream(f);
				OutputStreamWriter osw = new OutputStreamWriter(fos);
				Iterator<Entry<String, Delegation>> it = delegationRecord.entrySet().iterator();
				while (it.hasNext()) {
					Entry<String, Delegation> item = it.next();
					osw.write(item.getValue().writeInfo() + "\n");
				}		
				osw.close();
				fos.close();
		}
		else delegationFile = "NULL";

		if(securityKeyOrSignature != null) {
			PrintWriter writer = new PrintWriter("backup/payload/" + UID.split(".txt")[0] + "_payload.txt");
			writer.close();
			//save payload in specific file
			securityPayloadFile = "backup/payload/" + UID.split(".txt")[0] + "_payload.txt";
			BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(securityPayloadFile));
			bos.write(securityKeyOrSignature,0,securityKeyOrSignature.length);
			bos.close();	
		}
		else securityPayloadFile = "NULL";
		
		return (UID + ";" + Owner + ";" + length + ";" + CreatedTime + ";" + 
				LastModified + ";" + delegationFile + ";" + securityPayloadFile
				+ ";" + securityFlag) ;
	}
	
	public void removeDelegation(String user) {
		delegationRecord.remove(user);
	}
	
	public void addDelegation(String user, Delegation dele) {
		delegationRecord.put(user, dele);
	}
	
	public String getUID() {
		return UID;
	}
	public void setUID(String uID) {
		UID = uID;
	}
	
	public String getOwner() {
		return Owner;
	}
	public void setOwner(String owner) {
		Owner = owner;
	}
	public long getFileLength() {
		return fileLength;
	}
	public void setFileLength(long fileLength) {
		this.fileLength = fileLength;
	}
	public String getCreatedTime() {
		return CreatedTime;
	}
	public void setCreatedTime(String createdTime) {
		CreatedTime = createdTime;
	}
	public String getLastModified() {
		return LastModified;
	}
	public void setLastModified(String lastModified) {
		LastModified = lastModified;
	}
	
	public void showFileInfo() {
		System.out.println("UID: " + UID + ", File Owner: " + Owner + ", File length: " + fileLength +
		", Created Time: " + CreatedTime + ", Last Modified: " + LastModified + ", Security Flag:" + securityFlag);
	}

	public String getSecurityFlag() {
		return securityFlag;
	}

	public void setSecurityFlag(String securityFlag) {
		this.securityFlag = securityFlag;
	}

	public byte[] getSecurityKeyOrSignature() {
		return securityKeyOrSignature;
	}

	public void setSecurityKeyOrSignature(byte[] securityKeyOrSignature) {
		this.securityKeyOrSignature = securityKeyOrSignature;
	}

}
