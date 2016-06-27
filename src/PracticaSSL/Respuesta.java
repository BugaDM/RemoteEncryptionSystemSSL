package PracticaSSL;

import java.io.Serializable;
import java.util.GregorianCalendar;

public class Respuesta implements Serializable {
	private static final long serialVersionUID = -8560600329047091855L;
	private Paquete pq;
	private int idRegistro;
	private byte[] firmaServer;
	private GregorianCalendar selloTemporal;
	private int causaError;

	public Respuesta(int error) {
		this.causaError = error;
	}

	public Respuesta(int error, int id, byte[] firma, GregorianCalendar sello, Paquete pq) {
		this.causaError = error;
		this.idRegistro = id;
		this.firmaServer = firma;
		this.selloTemporal = sello;
		this.pq = pq;
	}

	public int getCausaError() {
		return this.causaError;
	}

	public byte[] getFirmaServer() {
		return this.firmaServer;
	}

	public int getIdRegistro() {
		return this.idRegistro;
	}

	public Paquete getPq() {
		return this.pq;
	}

	public GregorianCalendar getSelloTemporal() {
		return this.selloTemporal;
	}

	public void setCausaError(int CausaError) {
		this.causaError = CausaError;
	}

	public void setFirmaServer(byte[] firmaServer) {
		this.firmaServer = firmaServer;
	}

	public void setIdRegistro(int idRegistro) {
		this.idRegistro = idRegistro;
	}

	public void setPq(Paquete pq) {
		this.pq = pq;
	}

	public void setSelloTemporal(GregorianCalendar selloTemporal) {
		this.selloTemporal = selloTemporal;
	}

}
