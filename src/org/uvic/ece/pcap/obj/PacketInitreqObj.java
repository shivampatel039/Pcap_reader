package org.uvic.ece.pcap.obj;

public class PacketInitreqObj {
	private int       LocalDetailCalling;
	private int 	  propMaxServOutCalling;
	private int       propMaxServOutCalled;
	private int       propDataStructNestLevel;
	private int       propVerNo;
	private int       padding;
	private int	      propParamCBB;
	private byte[]    ServSupportCalling;
	private byte[]    Random;
	
	
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
    
    public int getpropParamCBB() {
        return propParamCBB;
    }

    public void setpropParamCBB(int propParamCBB) {
        this.propParamCBB = propParamCBB;
    }
    
    public byte[] getServSupportCalling() {
        return ServSupportCalling;
    }

    public void setServSupportCalling(byte[] ServSupportCalling) {
        this.ServSupportCalling = ServSupportCalling;
    }
    
    public int getpropVerNo() {
        return propVerNo;
    }

    public void setpropVerNo(int propVerNo) {
        this.propVerNo = propVerNo;
    }
    
    public int getpadding() {
        return padding;
    }

    public void setpadding(int padding) {
        this.padding = padding;
    }
    
    public byte[] getRandom() {
        return Random;
    }

    public void setRandom(byte[] Random) {
        this.Random = Random;
    }
    
    public String toString() {
		return LocalDetailCalling + "," + propMaxServOutCalling + ","+ propMaxServOutCalled + "," + propDataStructNestLevel + "," + propVerNo + "," + propParamCBB + "," +
			   "[" + ServSupportCalling[0] + ServSupportCalling[1]+ ServSupportCalling[2]+ ServSupportCalling[3]+ ServSupportCalling[4]+ ServSupportCalling[5]+ ServSupportCalling[6]
				+ ServSupportCalling[7]	+ ServSupportCalling[8]+ ServSupportCalling[9]+ ServSupportCalling[10] +"]";
	}
}
