package secusock;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;

public class Server implements Runnable
{
	private PrintWriter out = null;
	private BufferedReader in = null;
	
	public void run()
	{
		try
		{
			ServerSocket serverSocket = new ServerSocket(42069);
			Socket remoteSocket = serverSocket.accept();
			
			this.out = new PrintWriter(remoteSocket.getOutputStream(),
					true);
			this.in = new BufferedReader(new InputStreamReader(
					remoteSocket.getInputStream()));
		}
		catch (IOException e)
		{
		}
	}
}