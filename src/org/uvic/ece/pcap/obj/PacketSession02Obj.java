package org.uvic.ece.pcap.obj;

public class PacketSession02Obj {
	private int    Session02Length;
	private int    SPDUtype;
	
	public int getSPDUtype() {
        return SPDUtype;
    }
	
	public void setSPDUtype(int SPDUtype) {
        this.SPDUtype = SPDUtype;
    }
	
	public int getSession02Length() {
        return Session02Length;
    }
	
	public void setSession02Length(int Session02Length) {
        this.Session02Length = Session02Length;
    }
}
