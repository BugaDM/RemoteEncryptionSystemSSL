package PracticaSSL;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.GregorianCalendar;

public class Paquete implements Serializable {
	private static final long serialVersionUID = 7259390237606453160L;
	private String tipoPaquete;
	private String idPropietario;
	private String nombreDoc;
	private String tipoConfidencial;
	private int idRegistro;
	private byte[] documento;
	private byte[] firma_cliente;
	private byte[] firma_server;
	private GregorianCalendar selloTemporal;
	private ArrayList<String> errores = new ArrayList<String>();

	public Paquete(String idPropietario, String nombreDoc, String conf, byte[] documento, byte[] firma, String tipoPaquete) {
		this.idPropietario = idPropietario;
		this.nombreDoc = nombreDoc;
		this.tipoConfidencial = conf;
		this.documento = documento;
		this.firma_cliente = firma;
		this.setTipoPaquete(tipoPaquete);
	}

	public Paquete(String idPropietario, String nombreDoc, String conf, byte[] documento, byte[] firma, String tipoPaquete, int idRegistro) {
		this.idPropietario = idPropietario;
		this.nombreDoc = nombreDoc;
		this.tipoConfidencial = conf;
		this.documento = documento;
		this.firma_cliente = firma;
		this.setTipoPaquete(tipoPaquete);
		this.idRegistro = idRegistro;
	}

	public void addError(String string) {
		this.errores.add(string);

	}

	public boolean checkError() {
		if (this.errores.size() > 0)
			return true;
		return false;
	}

	public boolean confidencial() {
		if (this.tipoConfidencial.equals("PRIVADO"))
			return true;
		return false;
	}

	public byte[] getDocumento() {
		return this.documento;
	}

	public ArrayList<String> getErrores() {
		return this.errores;
	}

	public byte[] getFirma_server() {
		return this.firma_server;
	}

	public byte[] getFirmaCliente() {
		return this.firma_cliente;
	}

	public String getIdPropietario() {
		return this.idPropietario;
	}

	public int getIdRegistro() {
		return this.idRegistro;

	}

	public String getNombreDoc() {
		return this.nombreDoc;
	}

	public GregorianCalendar getSelloTemporal() {
		return this.selloTemporal;
	}

	public String getTipoConfidencial() {
		return this.tipoConfidencial;
	}

	public String getTipoPaquete() {
		return this.tipoPaquete;
	}

	public void setDocumento(byte[] documento) {
		this.documento = documento;
	}

	public void setFirma_server(byte[] firma_server) {
		this.firma_server = firma_server;
	}

	public void setFirmaCliente(byte[] firma) {
		this.firma_cliente = firma;
	}

	public void setIdPropietario(String idPropietario) {
		this.idPropietario = idPropietario;
	}

	public void setIdRegistro(int registro) {
		this.idRegistro = registro;

	}

	public void setNombreDoc(String nombreDoc) {
		this.nombreDoc = nombreDoc;
	}

	public void setSelloTemporal(GregorianCalendar selloTemporal) {
		this.selloTemporal = selloTemporal;
	}

	public void setTipoConfidencial(String tipoConfidencial) {
		this.tipoConfidencial = this.tipoPaquete;
	}

	public void setTipoPaquete(String tipoPaquete) {
		this.tipoPaquete = tipoPaquete;
	}

}
