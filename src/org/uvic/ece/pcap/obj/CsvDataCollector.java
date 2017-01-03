package org.uvic.ece.pcap.obj;

public class CsvDataCollector {
	
	private int[] 	  sourceIP;
	private int[] 	  destIP;
	private int   	  sourcePort;
	private int   	  destPort;
	private int       LocalDetailCalling;
	private int 	  propMaxServOutCalling;
	private int       propMaxServOutCalled;
	private int       propDataStructNestLevel;
	private int       propVerNo;
	private String	  propParamCBB;
	private int 	  Confirm_req_type;
	private int       Confirm_resp_type;
	

	public CsvDataCollector(int[] sourceIP, int[] destIP, int sourcePort,int destPort,int LocalDetailCalling,
							int propMaxServOutCalling,int propMaxServOutCalled,int propDataStructNestLevel,
							int propVerNo,String propParamCBB, int Confirm_req_type,int Confirm_resp_type){
		this.sourceIP = sourceIP;
		this.destIP = destIP;
		this.sourcePort = sourcePort;
		this.destPort = destPort;
		this.LocalDetailCalling = LocalDetailCalling;
		this.propMaxServOutCalling = propMaxServOutCalling;
		this.propMaxServOutCalled = propMaxServOutCalled;
		this.propDataStructNestLevel = propDataStructNestLevel;
		this.propVerNo = propVerNo;
		this.propParamCBB = propParamCBB;
		this.Confirm_req_type = Confirm_req_type;
		this.Confirm_resp_type = Confirm_resp_type;
		
	}
	
	public int[] getsourceIP() {
        return sourceIP;
    }

    public void setsourceIP(int[] sourceIP) {
        this.sourceIP = sourceIP;
    }

    public int[] getdestIP() {
        return destIP;
    }

    public void setdestIP(int[] destIP) {
        this.destIP = destIP;
    }
    
    public int getSourcePort() {
        return sourcePort;
    }

    public void setSourcePort(int sourcePort) {
        this.sourcePort = sourcePort;
    }

    public int getDestPort() {
        return destPort;
    }

    public void setDestPort(int destPort) {
        this.destPort = destPort;
    }
    
    public int getLocalDetailCalling() {
        return LocalDetailCalling;
    }

    public void setLocalDetailCalling(int LocalDetailCalling) {
        this.LocalDetailCalling = LocalDetailCalling;
    }
    
    public int getpropMaxServOutCalling() {
        return propMaxServOutCalling;
    }

    public void setpropMaxServOutCalling(int propMaxServOutCalling) {
        this.propMaxServOutCalling = propMaxServOutCalling;
    }
    
    public int getpropMaxServOutCalled() {
        return propMaxServOutCalled;
    }

    public void setpropMaxServOutCalled(int propMaxServOutCalled) {
        this.propMaxServOutCalled = propMaxServOutCalled;
    }
    
    public int getpropDataStructNestLevel() {
        return propDataStructNestLevel;
    }

    public void setpropDataStructNestLevel(int propDataStructNestLevel) {
        this.propDataStructNestLevel = propDataStructNestLevel;
    }
    
    public String getpropParamCBB() {
        return propParamCBB;
    }

    public void setpropParamCBB(String propParamCBB) {
        this.propParamCBB = propParamCBB;
    }
    
    public int getpropVerNo() {
        return propVerNo;
    }

    public void setpropVerNo(int propVerNo) {
        this.propVerNo = propVerNo;
    }
    
    public int getConfirm_req_type() {
		return Confirm_req_type;
	}

	public void setConfirm_req_type(int Confirm_req_type) {
		this.Confirm_req_type = Confirm_req_type;
	}

	public int getConfirm_resp_type() {
		return Confirm_resp_type;
	}

	public void setConfirm_resp_type(int Confirm_resp_type) {
		this.Confirm_resp_type = Confirm_resp_type;
	}
    
    public String toString() {
    	return  "\""+ sourceIP[0] + "."+ sourceIP[1] + "." + sourceIP[2] + "." + sourceIP[3] +"\""+ "," +"\""+ destIP[0] + "." + destIP[1] + "."+ destIP[2] + "."+ destIP[3] +"\""+ ","
    			+ "\""+ sourcePort + "\""+"," + "\""+destPort+"\""+","+ "\""+LocalDetailCalling + "\""+ "," + "\""+propMaxServOutCalling+ "\""+ ","+ "\""+propMaxServOutCalled + "\""+ "," 
    			+ "\""+ propDataStructNestLevel + "\""+ "," + "\""+ propVerNo+ "\""+ "," + "\""+ propParamCBB + "\""+ ","+"\""+ Confirm_req_type+ "\""+","+"\""+ Confirm_resp_type + "\"";
    } 
	
	
	
}
