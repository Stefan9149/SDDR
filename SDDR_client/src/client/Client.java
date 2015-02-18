package client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.UnknownHostException;

public class Client {
	public static void main(String[] args) throws Exception{
        //Creating a SocketClient object
        SocketClient client = new SocketClient ("localhost", 8080);
        try {
            //trying to establish connection to the server
            client.startSession();
            sendRequest(client);           
        } catch (UnknownHostException e) {
            System.err.println("Host unknown. Cannot establish connection");
        } catch (IOException e) {
            System.err.println("Cannot establish connection. Server may not be up. "+e.getMessage());
        }
    }

	private static void sendRequest(SocketClient client) throws Exception {
		while(!client.isClosed()) {
			//Get request from command line
			System.out.println("\nInput request to server: (Input HELP for help) (Input 'EXIT' to end the session)");
			String request = getUserInput();
				//legitimate requests:
				//HELP
				//PUT <Filename> <SecurityFlag>
				//GET <Filename>
				//SHOWCLIENTS
				//DELEGATE <Filename> <targetName> <expireTime> <delegateRights> <propagationFlag>
				//EXIT
				//UID
			if(request.equals("EXIT")){
				client.endSession();
			}
			else if(request.equals("HELP")) {
				System.out.println("Acceptable Requests:\n");
				System.out.println("HELP");
				System.out.println("SHOWCLIENTS");
				System.out.println("PUT <Filename> <SecurityFlag>");
				System.out.println("GET <Filename>");
				System.out.println("DELEGATE <Filename> <targetName> <expireTime> <delegateRights> <propagationFlag>");
				System.out.println("EXIT");
				System.out.println("UID");
				
			}
			else if(request.equals("SHOWCLIENTS")) {
				client.showRequest();
			}
			else if(request.equals("UID")) {
				client.computeUID();
			}
			else {
				String[] rq = request.split(" ");
				if(rq[0].equals("PUT")) {
					if(rq.length != 3) System.out.println("Improper Request!Should be like: PUT <Filename> <SecurityFlag>");
					else client.putRequest(rq[1], rq[2]);
				}
				else if(rq[0].equals("GET")) {
					if(rq.length != 2) System.out.println("Improper Request!Should be like: GET <Filename>");
					else client.getRequest(rq[1]);
				}
				
				else if(rq[0].equals("DELEGATE")) {
					if(rq.length != 6) {
						System.out.println("Improper Request!Should be like:\n");
						System.out.println("DELEGATE <Filename> <targetName> <expireTime> <delegateRights> <propagationFlag>");
					}
					else client.delegateRequest(rq[1], rq[2], rq[3], rq[4],rq[5]);
				}
				else {
					System.out.println("Improper Request!!!");
				}
			}
		}
	}
	
	private static String getUserInput() {
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
}
