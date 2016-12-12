package org.uvic.ece.pcap.obj;

public class Packet8823Obj {
	private byte[]    mode_select;
	private byte[]	  calling_selector;
	private byte[]	  called_selector;
	private byte[]	  context_def;
	private byte[]    Random;
	private int       padding;
	private int       presentation_req;
	private int       context_identifier;
	
	public byte[] getmode_select() {
        return mode_select;
    }

    public void setmode_select(byte[] mode_select) {
        this.mode_select = mode_select;
    }

    public byte[] getcalling_selector() {
        return calling_selector;
    }

    public void setcalling_selector(byte[] calling_selector) {
        this.calling_selector = calling_selector;
    }

    public byte[] getcalled_selector() {
        return called_selector;
    }

    public void setcalled_selector(byte[] called_selector) {
        this.called_selector = called_selector;
    }

    public byte[] getcontext_def() {
        return context_def;
    }

    public void setcontext_def(byte[] context_def) {
        this.context_def = context_def;
    }
    
    public byte[] getRandom() {
        return Random;
    }

    public void setRandom(byte[] Random) {
        this.Random = Random;
    }
    
    public int getpadding() {
        return padding;
    }

    public void setpadding(int padding) {
        this.padding = padding;
    }
    
    public int getpresentation_req() {
        return presentation_req;
    }

    public void setpresentation_req(int presentation_req) {
        this.presentation_req = presentation_req;
    }
    
    public int getcontext_identifier() {
        return context_identifier;
    }

    public void setcontext_identifiere(int context_identifier) {
        this.context_identifier = context_identifier;
    }

}
