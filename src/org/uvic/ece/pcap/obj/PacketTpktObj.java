package org.uvic.ece.pcap.obj;

public class PacketTpktObj {
	private int    Version;
	private int    Reserved;
	private int    TpktLength;
	private int    TpktObjlength;
	
	public int getVersion() {
        return Version;
    }
	
	public void setVersion(int Version) {
        this.Version = Version;
    }
	
	public int getReserved() {
        return Reserved;
    }
	
	public void setReserved(int Reserved) {
        this.Reserved = Reserved;
    }
	
	public int getTpktLength() {
        return TpktLength;
    }
	
	public void setTpktLength(int TpktLength) {
        this.TpktLength = TpktLength;
    }
	
	public int getTpktObjLength() {
        return TpktObjlength;
    }

    public void setTpktObjLength(int TpktObjlength) {
        this.TpktObjlength = TpktObjlength;
    }

}
