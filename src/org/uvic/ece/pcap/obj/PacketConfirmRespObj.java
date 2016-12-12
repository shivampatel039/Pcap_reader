package org.uvic.ece.pcap.obj;

public class PacketConfirmRespObj {
	
	private byte[]     TLV;
	private byte[]     RespData;
	private int        TLV_Len;
	private int  	   Tag;
	private int		   invokeID;
	private int		   RespType;
	
	
	public byte[] getTLV() {
		return TLV;
	}
	
	public void setTLV(byte[] TLV) {
		this.TLV = TLV;
	}
	
	public byte[] getRespData() {
		return RespData;
	}
	
	public void setRespData(byte[] RespData) {
		this.RespData = RespData;
	}
	
	public int getTLV_Len() {
		return TLV_Len;
	}
	
	public void setTLV_Len(int TLV_Len) {
		this.TLV_Len = TLV_Len;
	}
	
	public int getTag() {
		return Tag;
	}
	
	public void setTag(int Tag) {
		this.Tag = Tag;
	}
	
	public int getinvokeID() {
        return invokeID;
    }

    public void setinvokeID(int invokeID) {
        this.invokeID = invokeID;
    }
    
    public int getRespType() {
        return RespType;
    }

    public void setRespType(int RespType) {
        this.RespType = RespType;
    }
     
    public String toString() {
		return invokeID + "," + RespType;
	}
}
