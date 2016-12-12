package org.uvic.ece.pcap.obj;

public class Packet8650Obj {
	private int       padding;
	private int 	  Protocol_ver;
	private byte[]	  context_name;
	private byte[]	  called_title;
	private byte[]    AE_qualifier;
	private int       AP_identif;
	private int       AE_identif;
	private byte[]	  calling_title;
	private byte[]    Calling_ae_qualif;
	private byte[]    Random;
	private int       indirect_ref;
	
	
	public int getpadding() {
        return padding;
    }

    public void setpadding(int padding) {
        this.padding = padding;
    }
    
    public int getProtocol_ver() {
        return Protocol_ver;
    }

    public void setProtocol_ver(int Protocol_ver) {
        this.Protocol_ver = Protocol_ver;
    }
    
    public byte[] getcontext_name() {
        return context_name;
    }

    public void setcontext_name(byte[] context_name) {
        this.context_name = context_name;
    }
    
	
	public byte[] getcalled_title() {
        return called_title;
    }

    public void setcalled_title(byte[] called_title) {
        this.called_title = called_title;
    }
    
    public byte[] getAE_qualifier() {
        return AE_qualifier;
    }

    public void setAE_qualifier(byte[] AE_qualifier) {
        this.AE_qualifier = AE_qualifier;
    }

    public int getAP_identif() {
        return AP_identif;
    }

    public void setAP_identif(int AP_identif) {
        this.AP_identif = AP_identif;
    }
    
    public int getAE_identif() {
        return AE_identif;
    }

    public void setAE_identif(int AE_identif) {
        this.AE_identif = AE_identif;
    }
    
    public byte[] getcalling_title() {
        return calling_title;
    }

    public void setcalling_title(byte[] calling_title) {
        this.calling_title = calling_title;
    }
    
    public byte[] getCalling_ae_qualif() {
        return Calling_ae_qualif;
    }

    public void setCalling_ae_qualif(byte[] Calling_ae_qualif) {
        this.Calling_ae_qualif = Calling_ae_qualif;
    }
    
    public int getindirect_ref() {
        return indirect_ref;
    }

    public void setindirect_ref(int indirect_ref) {
        this.indirect_ref = indirect_ref;
    }
    
    public byte[] getRandom() {
        return Random;
    }

    public void setRandom(byte[] Random) {
        this.Random = Random;
    }
}
