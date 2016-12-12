package org.uvic.ece.pcap.obj;

public class Packet8823Obj1 {
	private int context_identif;
	private byte[] Random;
	
    public int getcontext_identif() {
        return context_identif;
    }

    public void setcontext_identif(int context_identif) {
        this.context_identif = context_identif;
    }
    
    public byte[] getRandom() {
        return Random;
    }

    public void setRandom(byte[] Random) {
        this.Random = Random;
    }
   
}
