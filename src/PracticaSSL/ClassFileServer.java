package PracticaSSL;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.security.KeyStore;

import javax.net.ServerSocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

/*********************************************************************
 * ClassFileServer.java -- a simple file server that can server Http get request
 * in both clear and secure channel
 *
 * The ClassFileServer implements a ClassServer that reads files from the file
 * system. See the doc for the "Main" method for how to run this server.
 ********************************************************************/

public class ClassFileServer extends ClassServer {

	private static int DefaultServerPort = 9001;
	private static String ks_Key;
	private static String ts_Key;

	/**********************************************************
	 * Constructs a ClassFileServer.
	 *
	 * @param path
	 *            the path where the server locates files
	 **********************************************************/
	public ClassFileServer(ServerSocket ss, String modo) throws IOException {
		super(ss,modo);
	}

	/******************************************************
	 * definirKeyStores()
	 *******************************************************/
	private static void definirKeyStores() {
		// Almacen de claves

		System.setProperty("javax.net.ssl.keyStore", "KEYS/SERVIDOR/servidor.jce");
		System.setProperty("javax.net.ssl.keyStoreType", "JCEKS");
		System.setProperty("javax.net.ssl.keyStorePassword", ks_Key);

		// Almacen de confianza

		System.setProperty("javax.net.ssl.trustStore", "KEYS/SERVIDOR/cacerts.jks");
		System.setProperty("javax.net.ssl.trustStoreType", "JKS");
		System.setProperty("javax.net.ssl.trustStorePassword", ts_Key);
	}

	/******************************************************
	 * getServerSocketFactory(String type) {}
	 *****************************************************/
	private static ServerSocketFactory getServerSocketFactory(String type) {

		if (type.equals("TLS")) {
			SSLServerSocketFactory ssf = null;

			try {

				// Establecer el keymanager para la autenticacion del servidor

				SSLContext ctx;
				KeyManagerFactory kmf;
				KeyStore ks;
				char[] contrasena = ks_Key.toCharArray();

				ctx = SSLContext.getInstance("TLS");
				kmf = KeyManagerFactory.getInstance("SunX509");

				ks = KeyStore.getInstance("JCEKS");
				ks.load(new FileInputStream("KEYS/SERVIDOR/servidor.jce"), contrasena);

				kmf.init(ks, contrasena);

				ctx.init(kmf.getKeyManagers(), null, null);

				ssf = ctx.getServerSocketFactory();
				return ssf;
			} catch (Exception e) {

				e.printStackTrace();
			}

		} else {
			System.out.println("Usando la Factoria socket por defecto (no SSL)");

			return ServerSocketFactory.getDefault();
		}

		return null;
	}

	/**
	 * Main ********************************************* Main method to create
	 * the class server that reads files. This takes two command line arguments,
	 * the port on which the server accepts requests and the root of the path.
	 * To start up the server: <
	 *
	 * java ClassFileServer <port> <path>
	 *
	 *
	 * <code>   new ClassFileServer(port, docroot);
	 * </code>
	 *
	 * @throws Exception
	 *****************************************************/
	public static void main(String args[]) throws Exception {

		ks_Key = args[0].trim();
		ts_Key = args[1].trim();
		String modo = args[2].trim();
		System.out.println("Contraseña key Store: "+ks_Key+"\nContraseña trust Store: "+ts_Key+"\nAlgoritmo Cifrado: "+modo);
		
		definirKeyStores();
		
		String type = "TLS";

		try {
			ServerSocketFactory ssf = ClassFileServer.getServerSocketFactory(type);

			ServerSocket ss = ssf.createServerSocket(DefaultServerPort);

			((SSLServerSocket) ss).setNeedClientAuth(true);

			new ClassFileServer(ss, modo);

		} catch (IOException e) {
			System.out.println("Unable to start ClassServer: " + e.getMessage());
			e.printStackTrace();
		}
	}

	

}
