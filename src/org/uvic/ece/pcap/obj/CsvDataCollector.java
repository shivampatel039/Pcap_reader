package org.uvic.ece.pcap.obj;

public class CsvDataCollector {
	
	private int[] sourceIP;
	private int[] destIP;
	private int   sourcePort;
	private int   destPort;	
	
	
	
	public CsvDataCollector(int[] sourceIP, int[] destIP, int sourcePort,int destPort){
		this.sourceIP = sourceIP;
		this.destIP = destIP;
		this.sourcePort = sourcePort;
		this.destPort = destPort;
		
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
    
    public String toString() {
    	return  "\""+ sourceIP[0] + "."+ sourceIP[1] + "." + sourceIP[2] + "." + sourceIP[3] +"\""+ "," +"\""+ destIP[0] + "." + destIP[1] + "."+ destIP[2] + "."+ destIP[3] +"\""+ ","
    			+ "\""+ sourcePort + "\""+"," + "\""+destPort+"\"";
    } 
	
	
	
}
