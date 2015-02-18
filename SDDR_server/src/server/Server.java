package server;

import java.io.IOException;

public class Server {
	public static void main(String[] args) throws Exception {
		int portNumber = 8080;
		
		try {
			SocketServer socketServer = new SocketServer(portNumber);
			socketServer.start();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}	
}
