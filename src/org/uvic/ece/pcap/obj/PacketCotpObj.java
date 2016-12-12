package org.uvic.ece.pcap.obj;

public class PacketCotpObj {
	private int    CotpLength;
	private int    PDUtype;
	private int    TPDU;
	
	public int getCotpLength() {
        return CotpLength;
    }
	
	public void setCotpLength(int CotpLength) {
        this.CotpLength = CotpLength;
    }
	
	public int getPDUtype() {
        return PDUtype;
    }
	
	public void setPDUtype(int PDUtype) {
        this.PDUtype = PDUtype;
    }
	
	public int getTPDU() {
        return TPDU;
    }
	
	public void setTPDU(int TPDU) {
        this.TPDU = TPDU;
    }
}
