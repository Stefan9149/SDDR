package client;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.Key;
import java.util.ArrayList;
import java.util.HashMap;

public class SocketClient {
	private String hostname;
    private int portWithServer;
    private Socket socketClient;
    private OutputStream outputStreamWithServer;
    private InputStream inputStreamWithServer;
    private String username;
	private char[] pwd = {'1','2','3','1','2','3'};
	private String myalias;
	private String jksPath;
	private Key sharedKey;
	private ArrayList<String> fileFromServer;
	private long beginTime;
	private long endTime;
	private HashMap<String, String> fileUID;

    public SocketClient(String hostname, int portWithServer){
        this.hostname = hostname;
        this.portWithServer = portWithServer;
    }

    //mapping default test files to UIDs
	private void configUID() {
		fileUID = new HashMap<String, String>();
        fileNameToUID("case1.txt");
        fileNameToUID("case2.txt");
        fileNameToUID("case3.txt");
        fileNameToUID("case4.txt");
        fileNameToUID("case5.txt");
        fileNameToUID("case6.txt");
        fileNameToUID("case7.txt");
        fileNameToUID("case8.txt");
        fileNameToUID("case9.txt");
        fileNameToUID("case10.txt");
        fileNameToUID("case11.txt");
        fileNameToUID("case12.txt");
	}
    
    public void startSession() throws Exception {
    	//Initialization, send username
        initialization();
		sendLoginRequest();
		fileFromServer = new ArrayList<String>();
		myalias = username;
		jksPath = "cs6238Project2/" + myalias+ ".jks";
		//Key Exchange
		chaClient channel = new chaClient(socketClient, pwd, myalias, jksPath);
		sharedKey =channel.startChannel();
		//System.out.println(sharedKey.toString());		
		getLoginResponse();
        configUID();
    }
    
	private void initialization() throws UnknownHostException, IOException {
		//Connecting to Server
		System.out.println("Attempting to connect to " + hostname + ":" + portWithServer);
        socketClient = new Socket(hostname, portWithServer);
        if(socketClient.isConnected()) {
            System.out.println("Connection Established");
        }
        //initialize I/O stream with server
		outputStreamWithServer = socketClient.getOutputStream();
		inputStreamWithServer = socketClient.getInputStream();	
	}

	private void getLoginResponse() throws Exception {
		//get response from server
		String serverResponse = new String(decrypt(receiveIn(inputStreamWithServer)));
		if(serverResponse.equals("Agree")) {
		    System.out.println("Login successfully!!!");
		}
		else {
			System.out.println("Login failed...");
			endSession();
		}
	}

	private void sendLoginRequest() throws Exception {
		//input/send out username
        System.out.println("Please input your username:(For testing, you should input 'client1'/'client2'/'client3'");
        username = getUserInput();
        while(!username.equals("client1") && !username.equals("client2") && !username.equals("client3")) {
        	System.out.println("No credential produced for this user, please input again, using the test cases!");
        	username = getUserInput();
        }
        //Login Request
		sendOutFirstTime(username, outputStreamWithServer);
		System.out.println("Login...");
	}
	
	//TODO: write back changes
	public void endSession() throws Exception {
    	System.out.println("Attempting to update changes made on gotten files");
    	//writeback changed file, if have rights to update
    	if(!fileFromServer.isEmpty()) {
	    	for(int i = 0; i < fileFromServer.size(); i++) {
	    		putRequest(fileFromServer.get(i), "CONFIDENTIALITY");
	    	}
    	}
		String exitCommand = "EXIT"; 
		sendOut(exitCommand, outputStreamWithServer);
    	inputStreamWithServer.close();
    	outputStreamWithServer.close();
    	socketClient.close();
    	System.out.println("End Session With Server");
    }
    
	public void putRequest(String UID, String SecurityFlag) throws Exception{		
		DataInputStream dis = new DataInputStream(inputStreamWithServer);
		//Check Input Format
		if(sendPUT(UID, SecurityFlag)) {
			respondPUT(UID, dis);
		}
	}

	public void getRequest(String UID) throws Exception{		
		DataInputStream dis = new DataInputStream(inputStreamWithServer);
		//Checked before
		sendGET(UID);
		respondGET(UID, dis);
	}

	public void showRequest() throws Exception {
		DataInputStream dis = new DataInputStream(inputStreamWithServer);
		//Checked before
		sendSHOW();
		respondSHOW(dis);
	}

	public void delegateRequest(String UID, String targetName, String expireTime, String rights, String propagation) throws Exception {
		DataInputStream dis = new DataInputStream(inputStreamWithServer);
		//Check Input Format
		if(sendDelegation(UID, targetName, expireTime, rights, propagation)) {
			respondDelegation(dis);
		}
	}

	private boolean sendDelegation(String UID, String targetName, String expireTime, String rights, String propagation) throws Exception {
		//Check request format
		try {
			long x = Long.valueOf(expireTime);
		} 
		catch (NumberFormatException e) {
			System.out.println("Wrong format for expiretime!! Should be a number(seconds)");
			return false;
		}
		if(!rights.equals("W") && !rights.equals("R") && !rights.equals("WR")) {
			System.out.println("Wrong format for access rights!! Should be: W/R/WR");
			return false;
		}
		if(!propagation.equals("TRUE") && !propagation.equals("FALSE")) {
			System.out.println("Wrong format for propagation flag!! Should be: TRUE/FALSE");
			return false;
		}
		//send out DELEGATE request	
		String delegateCommand = "DELEGATE " + UID + " " + targetName + " " +  expireTime + " " + rights + " " + propagation;
		sendOut(delegateCommand, outputStreamWithServer);
		System.out.println("Waiting for server's response...");
		return true;
	}	
	
    private void respondDelegation(DataInputStream dis) throws Exception {
		//get response from server
		String in = new String(decrypt(receiveIn(inputStreamWithServer)));	
        if(in.equals("Agree")) {
        	System.out.println("Granted, delegated the file...");
        }
        else {
        	String[] serverResponse = in.split(":");
        	//Can propagate, but limited
        	if(serverResponse[0].equals("Agree")) {
        		System.out.println(serverResponse[1]);
        		String choice = getUserInput();
        		if(choice.equals("Y")) {
        			sendOut("Y", outputStreamWithServer);
        			String[] sr = in.split(":");
        			if(sr[0].equals("Agree")) {
        				System.out.println("Granted, delegated the file...");
        			}
        			else {
        				sendOut("N", outputStreamWithServer);
            			String[] dd = in.split(":");
            			if(dd[0].equals("Deny")) {
            	        	System.out.println(serverResponse[1]);
            			}
        			}
        		}
        		else {
        			sendOut("N", outputStreamWithServer);
        			String[] sr = in.split(":");
        			if(sr[0].equals("Deny")) {
        	        	System.out.println(serverResponse[1]);
        			}
        		}
        	}
        	else {
	        	System.out.println("Unable to do so...Because");
	        	System.out.println(in);
	        	System.out.println(serverResponse[1]);
	        }
        }
	}
    
	private void respondSHOW(DataInputStream dis) throws Exception {
		//get response from server
		String clientList = new String(decrypt(receiveIn(inputStreamWithServer)));
        System.out.println("Existing Clients:");
        System.out.println(clientList);
	}

	private void sendSHOW() throws Exception {
		//construct SHOW request
		String showCommand = "SHOWCLIENTS"; 
		sendOut(showCommand, outputStreamWithServer);
		System.out.println("Waiting for server's response...");
		
	}
	private void respondPUT(String UID, DataInputStream dis) throws Exception {
		//get response from server
		String in = new String(decrypt(receiveIn(inputStreamWithServer)));	
        if(in.equals("Agree")) {
        	System.out.println("Granted, sent file to server!!!");
        	sendFile(UID);
        }
        else {
        	String[] serverResponse = in.split(":");
        	if (serverResponse[0].equals("Agree")){
        		System.out.println("Granted, " + serverResponse[1]);
        		sendFile(UID);
        	}
        	else {
        		System.out.println("Unable to do so...Because");
        		System.out.println(serverResponse[1]);
        	}
        }
        endTime = System.currentTimeMillis();
        System.out.println("Time for PUT request:" + (endTime - beginTime));
	}
	
	private boolean sendPUT(String UID, String SecurityFlag) throws Exception {
		if(!SecurityFlag.equals("CONFIDENTIALITY") && !SecurityFlag.equals("INTEGRITY") && !SecurityFlag.equals("NONE")){
			System.out.println("Incorrect securityFlag, should be: CONFIDENTIALITY/INTEGRITY/NONE");
			return false;
		}		
		//uid -> filename, check local file
		try {
		File send = new File(uidToFileName(UID));
		} catch (NullPointerException e) {

			System.out.println("No such file...");
			return false;
		}
		
		//construct PUT request
		String putCommand = "PUT " + UID + " " + SecurityFlag; 
		sendOut(putCommand, outputStreamWithServer);
		System.out.println("Waiting for server's response...");
		
		beginTime = System.currentTimeMillis();
		return true;
	}

	private void respondGET(String UID, DataInputStream dis)
			throws Exception {
		String in = new String(decrypt(receiveIn(inputStreamWithServer)));	
        if(in.equals("Agree")) {
        	checkOutsideFile(UID);
        	fileFromServer.add(UID);
        	saveFile(UID);
        	System.out.println("Granted, received the file!!!");
        }
        else {
        	String[] serverResponse = in.split(":");
        	System.out.println("Unable to do so...Because");
        	System.out.println(serverResponse[1]);
        }
        endTime = System.currentTimeMillis();
        System.out.println("Time for GET request:" + (endTime - beginTime));
	}

	private void sendGET(String UID) throws Exception {
		//construct GET request
		String getCommand = "GET " + UID;
		sendOut(getCommand, outputStreamWithServer);
		System.out.println("Waiting for server's response...");
		beginTime = System.currentTimeMillis();
	}
	
	public boolean isClosed() {
		return socketClient.isClosed();
	}
	

	private byte[] receiveIn(InputStream in) throws Exception {
		DataInputStream dIn = new DataInputStream(in);
		int length = dIn.readInt();                    
		byte[] loginRequest=null;
		if(length>0) {
			loginRequest = new byte[length];
		    dIn.readFully(loginRequest, 0, loginRequest.length); 
		}
		return loginRequest;
	}
	
	private String getUserInput() {
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        String temp = null;
        try {
        	temp = br.readLine();
        } catch (IOException ioe) {
            System.out.println("IO error trying to read the request!");
            System.exit(1);
        }
        return temp;
	}

	//Just for first touch with server, sent username, without secure channel
	private void sendOutFirstTime(String temp, OutputStream out) throws Exception {
		byte[] buffer = temp.getBytes();
		DataOutputStream dOut = new DataOutputStream(out);
        dOut.writeInt(buffer.length); 
        dOut.write(buffer);
	}
	
	private void sendOut(String temp, OutputStream out) throws Exception {
		byte[] buffer = temp.getBytes();
		byte[] cipher = encrypt(buffer);
		DataOutputStream dOut = new DataOutputStream(out);
        dOut.writeInt(cipher.length); 
        dOut.write(cipher);
	}
    
	private void sendFile(String UID) throws Exception {
		//uid->filename
		File send = new File(uidToFileName(UID));
		byte[] buffer = new byte[(int) send.length()];
		BufferedInputStream bis = new BufferedInputStream(new FileInputStream(send));
		bis.read(buffer, 0, buffer.length);
		sendOut(new String(buffer), outputStreamWithServer);
		bis.close();
	}

	private void saveFile(String UID) throws Exception {
		byte[] fileContent = receiveIn(inputStreamWithServer);
		byte[] plaintext = decrypt(fileContent);
		if(plaintext.length>0){
			BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(uidToFileName(UID)));//uid->filename
			bos.write(plaintext,0,plaintext.length);
			bos.close();
		}else{
			System.out.println("empty file");
		}
	}

	public byte[] encrypt(byte[] input) throws Exception {
		encryptChannel eChannel = new encryptChannel();
		return eChannel.encrypt(input, sharedKey);
	}
	
	public byte[] decrypt(byte[] input) throws Exception {
		encryptChannel eChannel = new encryptChannel();
		return eChannel.decrypt(input, sharedKey);
	}
	
	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}
	
	public void computeUID(){
		System.out.println("To get UID, please input the filename:");
		String name = getUserInput();
		String UID = fileNameToUID(name);
		System.out.println("The UID of this file name is: " + UID);
	}
	
	public String fileNameToUID(String filename) {
		String uid = filename.split(".txt")[0] + "_" +username + ".txt";
		fileUID.put(uid, filename);
		return uid;
	}

	public String uidToFileName(String uid) {
		return fileUID.get(uid);
	}

	//Add files from other clients into local mapping
	public void checkOutsideFile(String uid) {
		if(!uid.split("_")[1].equals(username+".txt")) {
			fileUID.put(uid, uid);
		}	
	}
}
