package org.uvic.ece.pcap.obj;

public class MMSTypeIdentifier {
	private int mmsType;
	private int TLV_Len;
	private byte[] TLV;
	
	
	public int getTLV_Len() {
		return TLV_Len;
	}
	
	public void setTLV_Len(int TLV_Len) {
		this.TLV_Len = TLV_Len;
	}
	
	public int getmmsType() {
		return mmsType;
	}
	
	public void setmmsType(int mmsType) {
		this.mmsType = mmsType;
	}
	
	public byte[] getTLV() {
        return TLV;
    }

    public void setTLV(byte[] TLV) {
        this.TLV = TLV;
    }
   
}
