package org.uvic.ece.pcap.obj;

public class PacketSession01Obj {
	private int    Session01Length;
	private int    SPDUtype;
	
	public int getSPDUtype() {
        return SPDUtype;
    }
	
	public void setSPDUtype(int SPDUtype) {
        this.SPDUtype = SPDUtype;
    }
	
	public int getSession01Length() {
        return Session01Length;
    }
	
	public void setSession01Length(int Session01Length) {
        this.Session01Length = Session01Length;
    }
}
