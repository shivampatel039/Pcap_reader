package org.uvic.ece.pcap.obj;

public class PacketSession01RemainingObj {

    private byte[] Connect_accept_item;
    private byte[] Session_req;
    private byte[] Calling_selector;
    private byte[] Called_selector;
    private int	   Param_type;
    private int    Param_length;

    public byte[] getConnect_accept_item() {
        return Connect_accept_item;
    }

    public void setConnect_accept_item(byte[] Connect_accept_item) {
        this.Connect_accept_item = Connect_accept_item;
    }

    public byte[] getSession_req() {
        return Session_req;
    }

    public void setSession_req(byte[] Session_req) {
        this.Session_req = Session_req;
    }
    
    public byte[] getCalling_selector() {
        return Calling_selector;
    }

    public void setCalling_selector(byte[] Calling_selector) {
        this.Calling_selector = Calling_selector;
    }

    public byte[] getCalled_selector() {
        return Called_selector;
    }

    public void setCalled_selector(byte[] Called_selector) {
        this.Called_selector = Called_selector;
    }

    public int getParam_type() {
        return Param_type;
    }

    public void setParam_type(int Param_type) {
        this.Param_type = Param_type;
    }
    
    public int getParam_length() {
        return Param_length;
    }

    public void setParam_length(int Param_length) {
        this.Param_length = Param_length;
    }
}
