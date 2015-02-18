package server;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.spec.IvParameterSpec;

public class SocketServer {
	//Functionality
	private ServerSocket serverSocket;
	private int port;
	private ConcurrentHashMap<String, Document> listOfDoc;
	private ConcurrentHashMap<String, Connection> connectedClients;
	//Security
	private static IvParameterSpec IV = new IvParameterSpec(new byte[16]);
	private static char[] pwd = {'1','2','3','1','2','3'};
	private static String myalias = "server";
	private static String jksPath = "cs6238Project2/server.jks";
	
	public SocketServer(int port) {
		this.port = port;
	}
	
	public void start() throws Exception {
		System.out.print("Starting the socket server at port:" + port);
		serverSocket = new ServerSocket(port);		
		Socket client = null;
		connectedClients = new ConcurrentHashMap<String, Connection>();
		File f = new File("backup/listOfDoc.txt");
		if(f.exists()) {
			System.out.println("\nFound existing file information, backing up...");
			listOfDoc = new ConcurrentHashMap<String, Document>();
			BufferedReader br = new BufferedReader(new FileReader(f));
			String line;
			while ((line = br.readLine()) != null) {
			   Document doc = new Document(line);			   
			   listOfDoc.put(doc.getUID(), doc);
			}
			br.close();
		}
		else {
			listOfDoc = new ConcurrentHashMap<String, Document>();
		}
		System.out.println("Waiting for clients...");
		while(true) {
			Connection connection;
			client = serverSocket.accept();
			System.out.println("\nA client connected, waiting for authentication...");
			connection = new Connection(client, listOfDoc, connectedClients);
			Thread t = new Thread(connection);
			t.start();
		}
	}

	public static char[] getPwd() {
		return pwd;
	}

	public static void setPwd(char[] pwd) {
		SocketServer.pwd = pwd;
	}

	public static String getMyalias() {
		return myalias;
	}

	public static void setMyalias(String myalias) {
		SocketServer.myalias = myalias;
	}

	public static String getJksPath() {
		return jksPath;
	}

	public static void setJksPath(String jksPath) {
		SocketServer.jksPath = jksPath;
	}

	public static IvParameterSpec getIV() {
		return IV;
	}

	public static void setIV(IvParameterSpec iV) {
		IV = iV;
	}
}
