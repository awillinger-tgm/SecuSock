package secusock;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;

public class Server
{
	private PrintWriter out = null;
	private BufferedReader in = null;
	
	public boolean start(int port)
	{
		if (port < 1 || port > 65536)
			return false;

		try
		{
			ServerSocket serverSocket = new ServerSocket(port);
			Socket remoteSocket = serverSocket.accept();
			
			this.out = new PrintWriter(remoteSocket.getOutputStream(),
					true);
			this.in = new BufferedReader(new InputStreamReader(
					remoteSocket.getInputStream()));

			return true;
		}
		catch (IOException e)
		{
			return false;
		}
	}
}