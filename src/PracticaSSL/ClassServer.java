package PracticaSSL;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.AlgorithmParameters;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Calendar;
import java.util.GregorianCalendar;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/************************************************************
 * ClassServer.java -- a simple file server that can serve Http get request in
 * both clear and secure channel
 *
 * Basado en ClassServer.java del tutorial/rmi
 ************************************************************/
public abstract class ClassServer implements Runnable {

	private static ServerSocket	server		= null;
	private static int			registro	= 1;

	static byte[] parametros;

	static String	keyStore;
	static String	KeyStoreType;
	static String	KeyStorePassword;
	static String	trustStore;
	static String	trustStoreType;
	static String	trustStorePassword;

	static String modo;

	/**
	 * Constructs a ClassServer based on <b>ss</b> and obtains a file's
	 * bytecodes using the method <b>getBytes</b>.
	 *
	 */
	protected ClassServer(ServerSocket ss, String modo) {

		// Variables
		keyStore = System.getProperty("javax.net.ssl.keyStore");
		KeyStoreType = System.getProperty("javax.net.ssl.keyStoreType");
		KeyStorePassword = System.getProperty("javax.net.ssl.keyStorePassword");

		trustStore = System.getProperty("javax.net.ssl.trustStore");
		trustStoreType = System.getProperty("javax.net.ssl.trustStoreType");
		trustStorePassword = System.getProperty("javax.net.ssl.trustStorePassword");

		server = ss;
		this.newListener();
		ClassServer.modo = modo;
	}

	private static byte[] cifrado(byte[] archivo, int id_clave) throws Exception {
		String provider = "SunJCE";
		String algoritmo = "AES";
		String transformacion;
		if (modo.equals("CBC"))
			transformacion = "/" + modo + "/PKCS5Padding";
		else
			transformacion = "/" + modo + "/NoPadding";
		System.out.println("Ejecutando modo " + transformacion);

		/************************************************************
		 * Generar y almacenar la clave
		 ************************************************************/
		// Extraemos la clave del keystore del servidor
		char[] key_password = "servidor".toCharArray();

		KeyStore ks;
		ks = KeyStore.getInstance("JCEKS");
		// Cargamos el keystore
		ks.load(new FileInputStream(keyStore), key_password);
		KeyStore.SecretKeyEntry pkEntry = (KeyStore.SecretKeyEntry) ks.getEntry("1",
				new KeyStore.PasswordProtection(key_password));
		byte[] kreg_raw = pkEntry.getSecretKey().getEncoded();

		SecretKeySpec secretKeySpec = new SecretKeySpec(kreg_raw, algoritmo);
		Cipher cifrador = Cipher.getInstance(algoritmo + transformacion);
		// Se cifra con la modalidad opaca de la clave
		cifrador.init(Cipher.ENCRYPT_MODE, secretKeySpec);

		// int longbloque;
		byte[] bloquecifrado = cifrador.update(archivo);
		// Hacer dofinal
		// byte bloquecifrado[] = cifrador.doFinal(archivo);
		if (provider.equals("SunJCE") && (algoritmo.equals("AES") || algoritmo.equals("Blowfish")
				|| algoritmo.equals("DES") || algoritmo.equals("DESede") || algoritmo.equals("DiffieHellman")
				|| algoritmo.equals("OAEP") || algoritmo.equals("PBEWithMD5AndDES")
				|| algoritmo.equals("PBEWithMD5AndTripleDES") || algoritmo.equals("PBEWithSHA1AndDESede")
				|| algoritmo.equals("PBEWithSHA1AndRC2_40") || algoritmo.equals("RC2"))) {
			AlgorithmParameters param = AlgorithmParameters.getInstance(algoritmo);
			param = cifrador.getParameters();

			byte[] paramSerializados = param.getEncoded();
			FileOutputStream fparametros = new FileOutputStream("parametros" + (registro - 1) + ".txt");
			fparametros.write(paramSerializados);
			fparametros.close();
			parametros = paramSerializados;

		}
		// Devolvemos el fichero cifrado
		return bloquecifrado;

	}

	/**
	 *
	 * @param ks
	 * @return
	 * @throws Exception
	 */
	@SuppressWarnings("resource")
	private static byte[] descifrado(byte[] fichero_cifrado, Integer id_cifrado) throws Exception {
		FileInputStream fparametros_in = new FileInputStream("parametros" + id_cifrado + ".txt");
		String provider = "SunJCE";
		String algoritmo = "AES";
		String transformacion;
		if (modo.equals("CBC"))
			transformacion = "/" + modo + "/PKCS5Padding";
		else
			transformacion = "/" + modo + "/NoPadding";
		System.out.println("Ejecutando modo " + transformacion);

		char[] key_password = "passphrase".toCharArray();
		KeyStore ks;
		ks = KeyStore.getInstance("JCEKS");
		// Cargamos el keystore
		ks.load(new FileInputStream(keyStore), key_password);
		KeyStore.SecretKeyEntry pkEntry = (KeyStore.SecretKeyEntry) ks.getEntry("secret",
				new KeyStore.PasswordProtection(key_password));
		byte[] kreg_raw = pkEntry.getSecretKey().getEncoded();

		SecretKeySpec secretKeySpec = new SecretKeySpec(kreg_raw, algoritmo);

		// DESCIFRAR
		// *****************************************************************************

		Cipher descifrador = Cipher.getInstance(algoritmo + transformacion, provider);

		// Leer los parametros si el algoritmo soporta parametros
		if (provider.equals("SunJCE") && (algoritmo.equals("AES") || algoritmo.equals("Blowfish")
				|| algoritmo.equals("DES") || algoritmo.equals("DESede") || algoritmo.equals("DiffieHellman")
				|| algoritmo.equals("OAEP") || algoritmo.equals("PBEWithMD5AndDES")
				|| algoritmo.equals("PBEWithMD5AndTripleDES") || algoritmo.equals("PBEWithSHA1AndDESede")
				|| algoritmo.equals("PBEWithSHA1AndRC2_40") || algoritmo.equals("RC2")
		// -- Aqui se introducirian otros algoritmos
		)) {
			AlgorithmParameters params = AlgorithmParameters.getInstance(algoritmo, provider);
			byte[] paramSerializados = new byte[fparametros_in.available()];
			fparametros_in.read(paramSerializados);
			params.init(paramSerializados);
			descifrador.init(Cipher.DECRYPT_MODE, secretKeySpec, params);
		} else {
			descifrador.init(Cipher.DECRYPT_MODE, secretKeySpec);
		}

		byte bloqueClaro[] = descifrador.update(fichero_cifrado);
		return bloqueClaro;
	}

	private static byte[] firmar_servidor(Paquete pq_server) throws Exception {
		byte[] archivo = pq_server.getDocumento();
		// Argumentos
		String alias_key = "duke";
		String key_pass = "passphrase";
		String ks_file = keyStore;

		String algoritmo = "MD5withRSA";

		// Variables para el KeyStore
		KeyStore ks;
		char[] ks_password = KeyStorePassword.toCharArray();
		char[] key_password = key_pass.toCharArray();

		// Obtener la clave privada del keystore

		ks = KeyStore.getInstance("JCEKS");
		// Cargamos el keystore
		ks.load(new FileInputStream(ks_file), ks_password);

		KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias_key,
				new KeyStore.PasswordProtection(key_password));

		PrivateKey privateKey = pkEntry.getPrivateKey();

		// Creamos un objeto para firmar/verificar

		Signature signer = Signature.getInstance(algoritmo);

		// Inicializamos el objeto para firmar
		signer.initSign(privateKey);

		// Para firmar primero pasamos el hash al mensaje (metodo "update")
		// y despues firmamos el hash (metodo sign).

		byte[] firma = null;

		signer.update(archivo);

		// Una vez se a�ade la firma a�adimos tambi�n
		// (idRegistro,selloTemporal,firmaCliente)

		String dia = String.valueOf(pq_server.getSelloTemporal().get(Calendar.DAY_OF_MONTH));
		String mes = String.valueOf(pq_server.getSelloTemporal().get(Calendar.MONTH) + 1);
		String ano = String.valueOf(pq_server.getSelloTemporal().get(Calendar.YEAR));
		String hora = String.valueOf(pq_server.getSelloTemporal().get(Calendar.HOUR_OF_DAY));
		String minuto = String.valueOf(pq_server.getSelloTemporal().get(Calendar.MINUTE));
		String segundo = String.valueOf(pq_server.getSelloTemporal().get(Calendar.SECOND));

		String fecha = dia + "//" + mes + "//" + ano + " " + hora + ":" + minuto + ":" + segundo;
		byte idRegistro = (byte) pq_server.getIdRegistro();
		byte[] selloTemporal = fecha.getBytes();
		byte[] firmaCliente = pq_server.getFirmaCliente();

		signer.update(idRegistro);
		signer.update(selloTemporal);
		signer.update(firmaCliente);
		firma = signer.sign();
		return firma;
	}

	private static Paquete getObject(InputStream is) throws Exception {
		ObjectInputStream ois = new ObjectInputStream(is);
		Paquete pq_cliente = (Paquete) ois.readObject();
		return (pq_cliente);
	}

	/**
	 * Guarda el paquete en el servidor.
	 *
	 * @param pq_server
	 * @throws Exception
	 */
	private static void guardar_documento(Paquete pq_server) throws Exception {

		File documento = new File("FICHEROS_SERV/SIGS/" + pq_server.getIdRegistro() + ".sig");
		System.out.println("Guardando en :" + documento.getAbsolutePath());
		OutputStream os = new FileOutputStream(documento);
		ObjectOutputStream oos = new ObjectOutputStream(os);
		oos.writeObject(pq_server);
		oos.close();
	}

	private static Paquete procesar_paquete(Paquete pq_cliente) throws Exception {

		// Creamos un nuevo paquete que sera la respuesta
		Paquete pq_server = pq_cliente;
		// System.out.println(pq_cliente.getIdPropietario());
		if (verificarFirma(pq_cliente.getFirmaCliente(), pq_cliente.getDocumento(), pq_cliente.getIdPropietario())) {
			// Se genera un nº de registro, un sello temporal y se firma el
			// documento.
			int idRegistro = registro++;
			pq_server.setIdRegistro(idRegistro);
			GregorianCalendar fecha = new GregorianCalendar();
			pq_server.setSelloTemporal(fecha);

			// Comprobamos si se necesita de cifrado.
			if (pq_server.confidencial()) {
				// Ciframos el documento
				// Guardamos la clave en su carpeta correspondiente
				long starttime = System.nanoTime();
				byte[] archivo_cifrado = cifrado(pq_server.getDocumento(), registro);
				System.out.println("Cifrado en: " + (System.nanoTime() - starttime) / 1000000 + " ms");
				pq_server.setDocumento(archivo_cifrado);

			}
			byte[] firma_servidor = firmar_servidor(pq_server);
			pq_server.setFirma_server(firma_servidor);

		} else {
			// Se devuelve un mensaje de error.
			pq_server.addError("Firma incorrecta");
		}
		return pq_server;
	}

	/**
	 * Recuperamos el documento del .sig y enviamos el paquete al cliente
	 *
	 * @param documento
	 * @throws Exception
	 */
	private static Paquete recuperar_documento(String id_documento) throws Exception {
		File doc = new File(id_documento);
		Paquete pq_cliente;
		if (!doc.exists()) {
			pq_cliente = new Paquete(null, null, null, null, null, "1");

		} else {
			FileInputStream FiS = new FileInputStream(doc);
			ObjectInputStream ois = new ObjectInputStream(FiS);
			pq_cliente = (Paquete) ois.readObject();
			ois.close();
		}
		return pq_cliente;

	}

	public static boolean verificarFirma(byte[] firma, byte[] archivo, String idpropietario) throws Exception {

		String algoritmo = "MD5withRSA";
		String ksPassword = System.getProperty("javax.net.ssl.trustStorePassword");
		String ks_file = System.getProperty("javax.net.ssl.trustStore");
		String keyName;
		if (idpropietario.contains("SANTIAG"))
			keyName = "certificado_santiago";
		else
			keyName = "certificado_cliente";
		// Variables para el KeyStore
		KeyStore ks;
		char[] ks_password = ksPassword.toCharArray();

		// Obtener la clave privada del keystore

		ks = KeyStore.getInstance("JCEKS");

		ks.load(new FileInputStream(ks_file), ks_password);

		/*******************************************************************
		 * Verificacion
		 ******************************************************************/

		System.out.println("***      Verificando:         *** ");

		// Creamos un objeto para verificar
		Signature verifier = Signature.getInstance(algoritmo);

		// Obtener la clave publica del keystore
		PublicKey publicKey = ks.getCertificate(keyName).getPublicKey();

		// Inicializamos el objeto para verificar

		verifier.initVerify(publicKey);
		// A�adimos todo el fichero al verificador

		verifier.update(archivo);

		boolean resultado = false;
		// Verificamos & resultado

		resultado = verifier.verify(firma);

		System.out.println();
		if (resultado == true)
			System.out.println("Firma CORRECTA");
		else
			System.out.println("Firma NO correcta");

		return resultado;
	}

	/********************************************************
	 * newListener() Create a new thread to listen.
	 *******************************************************/
	private void newListener() {
		(new Thread(this)).start();// Llamada a run.
	}

	/***************************************************************
	 * run() -- The "listen" thread that accepts a connection to the server,
	 * parses the header to obtain the file name and sends back the bytes for
	 * the file (or error if the file is not found or the response was
	 * malformed).
	 **************************************************************/
	@Override
	public void run() {
		Socket socket;

		// accept a connection
		try {
			socket = server.accept();
			System.out.println("Nueva peticion detectada:\n\t");
			InputStream is = socket.getInputStream();
			OutputStream os = socket.getOutputStream();
			try {

				int tipo_paquete = 0;

				Paquete pq_procesado = getObject(is);
				if (pq_procesado.getTipoPaquete().equals("REGISTRO"))
					tipo_paquete = 1;
				else if (pq_procesado.getTipoPaquete().equals("RECUPERAR")) {
					tipo_paquete = 2;

				}

				switch (tipo_paquete) {
				case 1:// REGISTRAR DOCUMENTO
					pq_procesado = procesar_paquete(pq_procesado);
					if (!pq_procesado.checkError()) {
						guardar_documento(pq_procesado);
						// Generamos respuesta v�lida.
						Respuesta respuesta = new Respuesta(0, pq_procesado.getIdRegistro(),
								pq_procesado.getFirma_server(), pq_procesado.getSelloTemporal(), pq_procesado);
						ObjectOutputStream oos = new ObjectOutputStream(os);
						oos.writeObject(respuesta);
					} else {
						Respuesta respuesta = new Respuesta(1);// Respuesta con
						// error 1,
						// firma
						// invalida.
						ObjectOutputStream oos = new ObjectOutputStream(os);
						oos.writeObject(respuesta);

					}
					break;
				case 2:// RECUPERAR DOCUMENTO
					System.out.println("Recuperando documento");
					Paquete pq_cliente_recuperado = recuperar_documento(
							"FICHEROS_SERV/SIGS/" + String.valueOf(pq_procesado.getIdRegistro() + ".sig"));
					// En caso de que no exista se env�a un paquete con
					// solamente el campo de error
					if (pq_cliente_recuperado.getTipoPaquete().equals("1")) {
						ObjectOutputStream oos = new ObjectOutputStream(os);
						oos.writeObject(pq_cliente_recuperado);
					} else {

						if (!pq_cliente_recuperado.confidencial()) {
							System.out.println("Recuperando documento libre");
							// Si no es confidencial, no es necesario
							// desencriptado
							pq_cliente_recuperado.setTipoPaquete("0");// Recuperado
							// correctamente
							ObjectOutputStream oos = new ObjectOutputStream(os);
							oos.writeObject(pq_cliente_recuperado);
						} else {
							System.out.println("Recuperando paquete confidencial");
							// Comprobamos que el que solicita el env�o del
							// paquete es un usuario leg�timo
							boolean permitido = false;
							if (pq_cliente_recuperado.getIdPropietario().equals(pq_procesado.getIdPropietario()))
								permitido = true;

							if (!permitido) {
								Paquete pq_no_permitido = new Paquete(null, null, null, null, null, "1");
								ObjectOutputStream oos = new ObjectOutputStream(os);
								oos.writeObject(pq_no_permitido);

							} else {
								byte[] archivo_descifrado = descifrado(pq_cliente_recuperado.getDocumento(),
										pq_procesado.getIdRegistro());
								pq_cliente_recuperado.setTipoPaquete("0");
								pq_cliente_recuperado.setDocumento(archivo_descifrado);
								pq_cliente_recuperado.setFirma_server(firmar_servidor(pq_cliente_recuperado));
								ObjectOutputStream oos = new ObjectOutputStream(os);
								oos.writeObject(pq_cliente_recuperado);
							}
						}
					}
					break;

				default:
					System.out.println("Tipo de peticion no valida");
					break;
				}

			} catch (Exception e) {
				e.printStackTrace();
			}

		} catch (IOException e) {
			System.out.println("Class Server died: " + e.getMessage());
			e.printStackTrace();
			return;
		}

		// Creamos un nuevo thread para la pr�xima conexi�n.
		this.newListener();

		try {
			System.out.println("Cerrando socket");
			socket.close();
		} catch (IOException e) {
		}
	}
}
