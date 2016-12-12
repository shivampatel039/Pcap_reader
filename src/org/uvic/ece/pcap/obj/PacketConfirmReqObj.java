package org.uvic.ece.pcap.obj;

public class PacketConfirmReqObj {
	
	private byte[]     TLV;
	private byte[]     ReqData;
	private int        TLV_Len;
	private int  	   Tag;
	private int		   invokeID;
	private int		   ReqType;
	
	
	public byte[] getTLV() {
		return TLV;
	}
	
	public void setTLV(byte[] TLV) {
		this.TLV = TLV;
	}
	
	public byte[] getReqData() {
		return ReqData;
	}
	
	public void setReqData(byte[] ReqData) {
		this.ReqData = ReqData;
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
    
    public int getReqType() {
        return ReqType;
    }

    public void setReqType(int ReqType) {
        this.ReqType = ReqType;
    }
     
     public String toString() {
		return invokeID + "," + ReqType;
	}
}
