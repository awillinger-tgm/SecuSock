package secusock;

import java.io.BufferedReader;
import java.io.InputStreamReader;

/**
 * The main entry point of the application, used when building the JAR.
 * 
 * @author Andreas Willinger
 * @version 20150129.1
 */
public class Start
{
	public static void main(String[] args)
	{
		System.out.println("Welcome to SecuSock!");
		System.out.println("Please select one of the following implementations:");
		System.out.println("\t[1] - Server");
		System.out.println("\t[2] - Client");
		System.out.print("\nYour choice: ");
		
		try
		{
			BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
			
			String fromUser = in.readLine();
			String ip, port;
			int choice = Integer.parseInt(fromUser);
			
			switch(choice)
			{
				case 1:
					System.out.print("\nPlease enter the port to listen on: ");
					port = in.readLine();
					
					Server.main(new String[]{port});
					
					break;
				case 2:
					System.out.print("\nPlease enter the IP the server is running on: ");
					ip = in.readLine();
					
					System.out.print("\nPlease enter the port the server is listening on: ");
					port = in.readLine();
					
					Client.main(new String[]{ip, port});
					break;
				default:
					System.err.println("The selected option is invalid!");
			}
		}
		catch(Exception ex)
		{
			System.err.println("Invalid input!");
		}
	}
}