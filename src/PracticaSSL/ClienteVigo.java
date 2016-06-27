package PracticaSSL;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Scanner;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

@SuppressWarnings("resource")
public class ClienteVigo {
	static String path = "";
	static SSLSocket socket;
	static String keyStore;
	static String KeyStoreType;
	static String KeyStorePassword;
	static String trustStore;
	static String trustStoreType;
	static String trustStorePassword;

	/******************************************************
	 * definirKeyStores()
	 *
	 * @param trustore_pass
	 * @param keystore_pass
	 *******************************************************/
	private static void definirKeyStores(String keystore_pass, String trustore_pass) {

		// Almacen de claves
		System.setProperty("javax.net.ssl.keyStore", "KEYS/CLIENTE_VIGO/cliente.jks");
		System.setProperty("javax.net.ssl.keyStoreType", "JKS");
		System.setProperty("javax.net.ssl.keyStorePassword", "cliente");

		// Almacen de confianza
		System.setProperty("javax.net.ssl.trustStore", "KEYS/CLIENTE_VIGO/cacerts.jks");
		System.setProperty("javax.net.ssl.trustStoreType", "JKS");
		System.setProperty("javax.net.ssl.trustStorePassword", "cacerts");

		// Variables
		keyStore = System.getProperty("javax.net.ssl.keyStore");
		KeyStoreType = System.getProperty("javax.net.ssl.keyStoreType");
		KeyStorePassword = System.getProperty("javax.net.ssl.keyStorePassword");

		trustStore = System.getProperty("javax.net.ssl.trustStore");
		trustStoreType = System.getProperty("javax.net.ssl.trustStoreType");
		trustStorePassword = System.getProperty("javax.net.ssl.trustStorePassword");

	}

	private static SSLSocket definirSocket(boolean configurar) throws UnknownHostException, IOException {
		SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();

		String host = "127.0.0.1";
		SSLSocket socket = (SSLSocket) factory.createSocket(host, 9001);
		if (!configurar)
			return socket;
		System.out.println("Crear socket, host @ 127.0.0.1:9001");

		System.out.println("              CONFIGURACIÓN SSL");
		System.out.println("Selecciona los parámetros deseados de la lista");

		String[] enabled = socket.getEnabledCipherSuites();
		HashMap<Integer, String> selec = new HashMap<Integer, String>();
		for (int i = 0; i < enabled.length; i++) {
			System.out.println(i + "->" + enabled[i]);
			selec.put(i, enabled[i]);

		}

		BufferedReader teclado = new BufferedReader(new InputStreamReader(System.in));
		Integer seleccion = Integer.parseInt(teclado.readLine());

		String[] CipherSuite = new String[enabled.length + 1];
		CipherSuite[0] = selec.get(seleccion);
		System.out.println("Has seleccionado:  " + CipherSuite[0] + "\nSe le dará la mayor prioridad posible.");
		// Cambiamos la prioridad de dicho algoritmo para ser el de más
		// prioridad
		for (int i = 0; i < CipherSuite.length - 1; i++)
			CipherSuite[i + 1] = enabled[i];
		socket.setEnabledCipherSuites(CipherSuite);

		SSLParameters params = socket.getSSLParameters();
		System.out.println("Deseas autentificación de cliente?(si/no)");
		if (teclado.readLine().equals("si"))
			socket.getSSLParameters().setNeedClientAuth(true);
		else
			socket.getSSLParameters().setNeedClientAuth(false);
		socket.setSSLParameters(params);

		return socket;
	}

	private static byte[] firma(String file_loc, String ks_loc) throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
			IOException, InvalidKeyException, SignatureException, UnrecoverableEntryException {
		// Archivo a firmar
		FileInputStream fmensaje = new FileInputStream(file_loc);
		// Argumentos
		String ks_pass = "cliente";
		String key_pass = "cliente";
		String alias_key = "pkcliente";
		String ks_file = ks_loc;

		String algoritmo = "MD5withRSA";

		int longbloque;
		byte bloque[] = new byte[1024];
		long filesize = 0;

		// Variables para el KeyStore
		KeyStore ks;
		char[] ks_password = ks_pass.toCharArray();
		char[] key_password = key_pass.toCharArray();

		// Obtener la clave privada del keystore

		ks = KeyStore.getInstance("JKS");
		// Cargamos el keystore
		ks.load(new FileInputStream(ks_file), ks_password);

		KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias_key, new KeyStore.PasswordProtection(key_password));

		PrivateKey privateKey = pkEntry.getPrivateKey();

		// Creamos un objeto para firmar/verificar

		Signature signer = Signature.getInstance(algoritmo);

		// Inicializamos el objeto para firmar
		signer.initSign(privateKey);

		// Para firmar primero pasamos el hash al mensaje (metodo "update")
		// y despues firmamos el hash (metodo sign).

		byte[] firma = null;

		while ((longbloque = fmensaje.read(bloque)) > 0) {
			filesize = filesize + longbloque;
			signer.update(bloque, 0, longbloque);
		}

		firma = signer.sign();

		fmensaje.close();
		return firma;
	}

	/**
	 * Recupera un documento que ha sido registrado previamente
	 *
	 * @param doc
	 * @throws IOException
	 * @throws KeyStoreException
	 * @throws CertificateException
	 * @throws NoSuchAlgorithmException
	 *             @
	 */
	private static Paquete generar_peticion(int idDoc) throws NoSuchAlgorithmException, CertificateException, KeyStoreException,
	IOException {
		/*
		 * Debemos recuperar el documento doc, que ha sido registrado mediante
		 * nuestra identidad (Extraída del keystore), para ello enviamos
		 * recuperar_documento(idPropietario,idRegistro) al servidor.
		 */

		// Recuperamos nuestra identidad.
		String identidad = getNombreCertificado();
		Paquete pq_recuperar = new Paquete(identidad, null, null, null, null, "RECUPERAR", idDoc);
		System.out.println("Pidiendo documento: " + pq_recuperar.getIdRegistro());
		return pq_recuperar;

	}

	private static byte[] get_datos_verificar(Paquete pq_respuesta) throws IOException {
		String dia = String.valueOf(pq_respuesta.getSelloTemporal().get(Calendar.DAY_OF_MONTH));
		String mes = String.valueOf(pq_respuesta.getSelloTemporal().get(Calendar.MONTH) + 1);
		String año = String.valueOf(pq_respuesta.getSelloTemporal().get(Calendar.YEAR));
		String hora = String.valueOf(pq_respuesta.getSelloTemporal().get(Calendar.HOUR_OF_DAY));
		String minuto = String.valueOf(pq_respuesta.getSelloTemporal().get(Calendar.MINUTE));
		String segundo = String.valueOf(pq_respuesta.getSelloTemporal().get(Calendar.SECOND));

		String fecha = dia + "//" + mes + "//" + año + " " + hora + ":" + minuto + ":" + segundo;
		byte idRegistro = (byte) pq_respuesta.getIdRegistro();
		byte[] selloTemporal = fecha.getBytes();
		byte[] firmaCliente = pq_respuesta.getFirmaCliente();
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		outputStream.write(pq_respuesta.getDocumento());
		outputStream.write(idRegistro);
		outputStream.write(selloTemporal);
		outputStream.write(firmaCliente);
		return outputStream.toByteArray();
	}

	/**
	 * Teniendo en cuenta que se supone la existencia de un solo certificado en
	 * el keystore, se recupera el nombre (OU/O) de este certificado, y se
	 * devuelve dicho nombre.
	 *
	 * @return @
	 * @throws IOException
	 * @throws CertificateException
	 * @throws NoSuchAlgorithmException
	 * @throws KeyStoreException
	 */
	private static String getNombreCertificado() throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {
		String full_name = null;
		File file = new File(keyStore);
		FileInputStream is = new FileInputStream(file);
		KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
		String password = KeyStorePassword;
		keystore.load(is, password.toCharArray());

		Enumeration<String> enumeration = keystore.aliases();
		while (enumeration.hasMoreElements()) {
			String alias = enumeration.nextElement();
			X509Certificate certificate = (X509Certificate) keystore.getCertificate(alias);
			full_name = certificate.getSubjectX500Principal().getName();
			String[] splat = full_name.split(",");
			for (String element : splat) {
				if (element.startsWith("OU") || element.startsWith("O")) {
					full_name = element.substring(2, element.length() - 1);
				}
			}
			break;

		}
		return full_name;

	}

	/**
	 * Guarda en disco el documento recuperado del servidor
	 *
	 * @param pq_respuesta
	 * @throws IOException
	 */
	private static void guardar_documento(Paquete pq_respuesta) throws IOException {
		byte[] archivo = pq_respuesta.getDocumento();
		File fich = new File("CLIENTE_VIGO/" + pq_respuesta.getNombreDoc());
		System.out.println(fich.getAbsolutePath());
		FileOutputStream FoS = new FileOutputStream(fich);
		FoS.write(archivo);
		FoS.close();

	}

	private static Respuesta leerRespuesta(InputStream inputStream) throws ClassNotFoundException, IOException {
		ObjectInputStream ois = new ObjectInputStream(inputStream);
		Respuesta res = (Respuesta) ois.readObject();
		return (res);
	}

	public static void main(String[] args) {
		// Documentos disponibles para ser recuperados
		try {

			// Inicializamos el lugar donde se guardarán los datos recibidos del
			// servidor.
			path = args[1];
			// Inicializamos keystores y socket.
			String keystore_pass = args[3];
			String trustore_pass = args[4];
			definirKeyStores(keystore_pass, trustore_pass);

			int reqArg = 0;
			boolean configurar = true;
			do {
				socket = definirSocket(configurar);
				configurar = false;

				// Protocolo SSL Handshake
				socket.startHandshake();
				// Enviamos la petición del archivo, se implementa un menú.
				reqArg = menu();
				Scanner teclado = new Scanner(System.in);
				switch (reqArg) {
				case 1:// registrar documento
					String fichero = mostrar_documentos_disponibles();
					if (fichero != null) {

						File fich_registrar = new File(fichero);
						System.out.println("Deseas confidencialidad?");
						boolean confidencial = false;
						if (teclado.nextLine().equals("si"))
							confidencial = true;
						registrarDocumento(confidencial, fich_registrar);
						Respuesta res = leerRespuesta(socket.getInputStream());

						System.out.println("Estado de registro: " + res.getCausaError());
						if (res.getCausaError() == 0)
							System.out.println("Aceptado sin errores.");
						if (res.getCausaError() == 1) {
							System.out.println("El servidor no ha podido verificar nuestra firma.");
							break;
						}
						System.out.println("Verificando firma del registrador:");
						long startTime = System.nanoTime();
						boolean verificar = verificarFirma(res.getFirmaServer(), get_datos_verificar(res.getPq()));

						if (verificar) {
							long duration = ((System.nanoTime() - startTime) / 1000000);
							System.out.println("Verificado en " + duration + " ms");
							System.out.println("Documento registrado con éxito:");
							System.out.println("\tID_REG: " + res.getIdRegistro());
							System.out.println("\tSELLO_TEMP: " + res.getSelloTemporal().getTime());
							System.out.print("\tSIG_REGISTRADOR: ");
							for (int j = 0; j < res.getFirmaServer().length; j++)
								System.out.print(res.getFirmaServer()[j]);
							System.out.println();
							fich_registrar.delete();

						} else {
							System.out.println("No se puede verificar la firma, no se ha registrado el documento.");
						}

						break;
					}
				case 2: // recuperar documento
					System.out.println("Introduzca ID del documento a recuperar.");

					int doc = Integer.parseInt(teclado.nextLine());
					// Se genera el paquete de petición
					Paquete pq_peticion = generar_peticion(doc);
					// Se envía el paquete
					sendObject(socket, pq_peticion);
					// Se recibe la respuesta
					Paquete pq_respuesta = recuperar_documento(socket.getInputStream());
					if (pq_respuesta.getTipoPaquete().equals("0")) {
						// Verificamos
						long startTime = System.nanoTime();
						boolean verificado = verificarFirma(pq_respuesta.getFirma_server(), get_datos_verificar(pq_respuesta));
						long duration = ((System.nanoTime() - startTime) / 1000000);
						System.out.println("Verificado en " + duration + " ms");

						if (verificado) {
							System.out.println("DOCUMENTO RECUPERADO CORRECTAMENTE");
							System.out.println("\tID_REG: " + pq_respuesta.getIdRegistro());
							System.out.println("\tSELLO_TEMP: " + pq_respuesta.getSelloTemporal().getTime());
							System.out.print("\tSIG_REGISTRADOR: ");
							for (int j = 0; j < pq_respuesta.getFirma_server().length; j++)
								System.out.print(pq_respuesta.getFirma_server()[j]);
							System.out.println();
							guardar_documento(pq_respuesta);

						} else
							System.out.println("Firma incorrecta, no se ha recuperado el documento correctamente.");
					} else {
						System.out.println("Código de error: " + pq_respuesta.getTipoPaquete());
						if (pq_respuesta.getTipoPaquete().equals("1"))
							System.out.println("DOCUMENTO NO EXISTE");
					}

					break;
				}
			} while (reqArg != 3);
			socket.close();

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private static int menu() {
		int ret = 0;
		Scanner teclado = new Scanner(System.in);
		System.out.println("\n\n\n\n1. Registrar documento \n2. Recuperar documento \n3. Salir");
		String entrada = teclado.nextLine();
		if (!entrada.equals(""))
			ret = Integer.parseInt(entrada);
		if (ret < 1 || ret > 3)
			menu();
		return ret;
	}

	private static String mostrar_documentos_disponibles() {

		HashMap<Integer, String> ficheros = new HashMap<Integer, String>();
		Scanner teclado = new Scanner(System.in);
		System.out.println("Documentos disponibles para registro:");
		File folder = new File(path + "/");
		int i = 1;
		if (folder.listFiles().length == 0) {
			System.out.println("SIN DOCUMENTOS");
			return null;
		}
		for (final File fileEntry : folder.listFiles()) {
			ficheros.put(i, fileEntry.getAbsolutePath());
			System.out.println(i++ + "->" + fileEntry.getName());
		}
		int seleccion = Integer.parseInt(teclado.nextLine());
		if (ficheros.containsKey(seleccion))
			return ficheros.get(seleccion);
		else
			return null;

	}

	/**
	 * Recibe la respuesta a la petición de recuperar documento desde el
	 * servidor
	 *
	 * @param inputStream
	 * @throws IOException
	 * @throws ClassNotFoundException
	 */
	private static Paquete recuperar_documento(InputStream is) throws IOException, ClassNotFoundException {
		ObjectInputStream ois = new ObjectInputStream(is);
		Paquete pq_recuperar = (Paquete) ois.readObject();
		return (pq_recuperar);

	}

	/**
	 *
	 * @param file
	 * @throws IOException
	 * @throws KeyStoreException
	 * @throws CertificateException
	 * @throws NoSuchAlgorithmException
	 * @throws UnrecoverableEntryException
	 * @throws SignatureException
	 * @throws InvalidKeyException
	 * @throws ClassNotFoundException
	 *             @
	 */
	private static void registrarDocumento(Boolean tipoConfidencial, File file) throws IOException, NoSuchAlgorithmException,
	CertificateException, KeyStoreException, InvalidKeyException, SignatureException, UnrecoverableEntryException,
	ClassNotFoundException {
		// Firmamos
		byte[] firma = firma(file.getAbsolutePath(), keyStore);
		// Extraemos id propietario
		String idPropietario = getNombreCertificado();
		// certificado.
		String nombreDoc = file.getName();
		String Confidencial;
		if (tipoConfidencial)
			Confidencial = "PRIVADO";
		else
			Confidencial = "PUBLICO";
		byte[] fichero = new byte[(int) file.length()];

		FileInputStream FiS = new FileInputStream(file);
		FiS.read(fichero);
		FiS.close();
		Paquete pq = new Paquete(idPropietario, nombreDoc, Confidencial, fichero, firma, "REGISTRO");
		// Y lo enviamos
		sendObject(socket, pq);
	}

	/**
	 * Envía un paquete de registro al sevidor que contiene todos los datos
	 * necesarios para el registro.
	 *
	 * @param socket
	 *            Socket
	 * @param arg
	 *            Fichero solicitado al servidor
	 * @throws IOException
	 */

	private static void sendObject(SSLSocket s, Paquete to) throws IOException, ClassNotFoundException {
		OutputStream os = s.getOutputStream();
		ObjectOutputStream oos = new ObjectOutputStream(os);
		oos.writeObject(to);
	}

	public static boolean verificarFirma(byte[] firma, byte[] archivo) throws SignatureException, KeyStoreException,
	NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, InvalidKeyException {
		String algoritmo = "MD5withRSA";
		String ksPassword = System.getProperty("javax.net.ssl.trustStorePassword");
		String ks_file = System.getProperty("javax.net.ssl.trustStore");
		String keyName = "certificado_servidor";
		// Variables para el KeyStore
		KeyStore ks;
		char[] ks_password = ksPassword.toCharArray();

		// Obtener la clave pública del keystore

		ks = KeyStore.getInstance("JCEKS");
		ks.load(new FileInputStream(ks_file), ks_password);

		// Creamos un objeto para verificar
		Signature verifier = Signature.getInstance(algoritmo);

		// Obtener la clave publica del keystore
		PublicKey publicKey = ks.getCertificate(keyName).getPublicKey();

		// Inicializamos el objeto para verificar
		verifier.initVerify(publicKey);

		// Añadimos todo el fichero al verificador
		verifier.update(archivo);

		// Verificamos & resultado
		boolean resultado = verifier.verify(firma);

		System.out.println();
		if (resultado == true)
			System.out.println("Firma Registrador CORRECTA");
		else
			System.out.println("Firma Registrador INCORRECTA");

		return resultado;
	}

}// Fin clase
