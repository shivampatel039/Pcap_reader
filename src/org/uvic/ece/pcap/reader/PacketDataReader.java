package org.uvic.ece.pcap.reader;

import java.util.ArrayList;
import java.util.List;

import org.uvic.ece.pcap.obj.*;
import org.uvic.ece.pcap.reader.buffer.BufferReader;

public class PacketDataReader {
	
    private final BufferReader bufferReader;

    public PacketDataReader(BufferReader bufferReader) {
        this.bufferReader = bufferReader;
    }

    public PacketEthernetObj parseEthernet() throws Exception {
        PacketEthernetObj packetEthernetObj = new PacketEthernetObj();

        packetEthernetObj.setSource(bufferReader.read(6));
        packetEthernetObj.setDest(bufferReader.read(6));
        packetEthernetObj.setType(bufferReader.readUint16());

        return packetEthernetObj;
    }

    public PacketIpv4Obj parseIpv4() throws Exception {
        PacketIpv4Obj packetIpv4Obj = new PacketIpv4Obj();

        int data = bufferReader.readUint8();
        packetIpv4Obj.setType(data >> 4 & 0xf);
        packetIpv4Obj.setHeaderLength(data & 0xf);
        bufferReader.readInt8();
        packetIpv4Obj.setTotalLength(bufferReader.readUint16());
        packetIpv4Obj.setIdentification(bufferReader.readUint16());
        bufferReader.readInt16();
        packetIpv4Obj.setTimeToLive(bufferReader.readUint8());
        packetIpv4Obj.setProtocol(bufferReader.readUint8());
        packetIpv4Obj.setHeaderCheckSum(bufferReader.readUint16());
        int[] source = new int[4];
        for (int i = 0; i < 4; i++)
            source[i] = bufferReader.readUint8();
        packetIpv4Obj.setSource(source);
        int[] dest = new int[4];
        for (int i = 0; i < 4; i++)
            dest[i] = bufferReader.readUint8();
        packetIpv4Obj.setDest(dest);

        return packetIpv4Obj;
    }

    public PacketTcpObj parseTcp() throws Exception {
        PacketTcpObj packetTcpObj = new PacketTcpObj();

        packetTcpObj.setSourcePort(bufferReader.readUint16());
        packetTcpObj.setDestPort(bufferReader.readUint16());
        packetTcpObj.setSequenceNum(bufferReader.readUint32());
        packetTcpObj.setAckNum(bufferReader.readUint32());
        packetTcpObj.setHeaderLength(bufferReader.readUint8() / 4);
        bufferReader.readUint8();
        packetTcpObj.setWindowSize(bufferReader.readUint16());
        packetTcpObj.setCheckSum(bufferReader.readUint16());
        packetTcpObj.setUrgentPointer(bufferReader.readUint16());

        int optionLength = packetTcpObj.getHeaderLength() - PacketTcpObj.HEADER_LENGTH;
        if (optionLength > 0) {
            byte[] options = new byte[optionLength];
            bufferReader.get(options);
            packetTcpObj.setOptions(options);
        }

        return packetTcpObj;
    }
    
    public PacketTpktObj parseTpkt() throws Exception {
    	PacketTpktObj packetTpktObj = new PacketTpktObj();
    	
    	packetTpktObj.setVersion(bufferReader.readUint8());
    	packetTpktObj.setReserved(bufferReader.readUint8());
    	packetTpktObj.setTpktLength(bufferReader.readUint16());
    	
    	return packetTpktObj;
    }
    
    public PacketCotpObj parseCotp() throws Exception {
    	PacketCotpObj packetCotpObj = new PacketCotpObj();
    	
    	packetCotpObj.setCotpLength(bufferReader.readUint8());
    	packetCotpObj.setPDUtype(bufferReader.readUint8());
    	packetCotpObj.setTPDU(bufferReader.readUint8());
    	
    	return packetCotpObj;
    } 

    public PacketSession01Obj parseSession01() throws Exception {
    	PacketSession01Obj packetSession01Obj = new PacketSession01Obj();
    	
    	packetSession01Obj.setSPDUtype(bufferReader.readUint8());
    	packetSession01Obj.setSession01Length(bufferReader.readUint8());
    	
    	return packetSession01Obj;
    } 
    
    public PacketSession01RemainingObj parseSession01Remaining() throws Exception {
    	PacketSession01RemainingObj packetSession01RemainingObj = new PacketSession01RemainingObj();
    	
    	packetSession01RemainingObj.setConnect_accept_item(bufferReader.read(8));
    	packetSession01RemainingObj.setSession_req(bufferReader.read(4));
    	packetSession01RemainingObj.setCalling_selector(bufferReader.read(4));
    	packetSession01RemainingObj.setCalled_selector(bufferReader.read(4));
    	packetSession01RemainingObj.setParam_type(bufferReader.readUint8());
    	packetSession01RemainingObj.setParam_length(bufferReader.readUint8());
    	
    	return packetSession01RemainingObj;
    
    }
    
    public Packet8823Obj parse8823() throws Exception {
    	Packet8823Obj packet8823Obj = new Packet8823Obj();
    	
    	packet8823Obj.setRandom(bufferReader.read(3)); // Reading unidentified bytes in the pcap file
    	packet8823Obj.setRandom(bufferReader.read(2)); // Reading unidentified bytes in the pcap file
    	packet8823Obj.setmode_select(bufferReader.read(3));
    	packet8823Obj.setRandom(bufferReader.read(3)); // Reading unidentified bytes in the pcap file
    	packet8823Obj.setRandom(bufferReader.read(2)); // Reading unidentified bytes in the pcap file
    	packet8823Obj.setcalling_selector(bufferReader.read(4));
    	packet8823Obj.setRandom(bufferReader.read(2)); // Reading unidentified bytes in the pcap file
    	packet8823Obj.setcalled_selector(bufferReader.read(4));
    	packet8823Obj.setRandom(bufferReader.read(2)); // Reading unidentified bytes in the pcap file
    	packet8823Obj.setcontext_def(bufferReader.read(35));
    	packet8823Obj.setRandom(bufferReader.read(2)); // Reading unidentified bytes in the pcap file
    	packet8823Obj.setpadding(bufferReader.readUint8());
    	packet8823Obj.setpresentation_req(bufferReader.readUint8());
    	packet8823Obj.setRandom(bufferReader.read(2)); // Reading unidentified bytes in the pcap file
    	packet8823Obj.setRandom(bufferReader.read(4)); // Reading unidentified bytes in the pcap file
    	packet8823Obj.setcontext_identifiere(bufferReader.readUint8());
    	packet8823Obj.setRandom(bufferReader.read(2)); // Reading unidentified bytes in the pcap file
    	
    	return packet8823Obj;
    }
    
    public Packet8650Obj parse8650() throws Exception {
    	Packet8650Obj packet8650Obj = new Packet8650Obj();
    	
    	packet8650Obj.setRandom(bufferReader.read(4)); // Reading unidentified bytes in the pcap file
    	packet8650Obj.setpadding(bufferReader.readUint8());
    	packet8650Obj.setProtocol_ver(bufferReader.readUint8());
    	packet8650Obj.setRandom(bufferReader.read(4)); // Reading unidentified bytes in the pcap file
    	packet8650Obj.setcontext_name(bufferReader.read(5));
    	packet8650Obj.setRandom(bufferReader.read(2)); // Reading unidentified bytes in the pcap file
    	packet8650Obj.setcalled_title(bufferReader.read(6));
    	packet8650Obj.setRandom(bufferReader.read(2)); // Reading unidentified bytes in the pcap file
    	packet8650Obj.setAE_qualifier(bufferReader.read(3));
    	packet8650Obj.setRandom(bufferReader.read(4)); // Reading unidentified bytes in the pcap file
    	packet8650Obj.setAP_identif(bufferReader.readUint8());
    	packet8650Obj.setRandom(bufferReader.read(4)); // Reading unidentified bytes in the pcap file
    	packet8650Obj.setAE_identif(bufferReader.readUint8());
    	packet8650Obj.setRandom(bufferReader.read(2)); // Reading unidentified bytes in the pcap file
    	packet8650Obj.setcalling_title(bufferReader.read(6));
    	packet8650Obj.setRandom(bufferReader.read(2)); // Reading unidentified bytes in the pcap file
    	packet8650Obj.setCalling_ae_qualif(bufferReader.read(3));
    	packet8650Obj.setRandom(bufferReader.read(6)); // Reading unidentified bytes in the pcap file
    	packet8650Obj.setindirect_ref(bufferReader.readUint8());
    	packet8650Obj.setRandom(bufferReader.read(2)); // Reading unidentified bytes in the pcap file
    	
    	return packet8650Obj;
    }
    
    public PacketInitreqObj parseInitreq() throws Exception {
    	PacketInitreqObj packetInitreqObj = new PacketInitreqObj();
    	
    	packetInitreqObj.setRandom(bufferReader.read(2)); // Reading unidentified bytes in the pcap file
    	packetInitreqObj.setLocalDetailCalling(bufferReader.readUint16());
    	packetInitreqObj.setRandom(bufferReader.read(2)); // Reading unidentified bytes in the pcap file
    	packetInitreqObj.setpropMaxServOutCalling(bufferReader.readUint16());
    	packetInitreqObj.setRandom(bufferReader.read(2)); // Reading unidentified bytes in the pcap file
    	packetInitreqObj.setpropMaxServOutCalled(bufferReader.readUint16());
    	packetInitreqObj.setRandom(bufferReader.read(2)); // Reading unidentified bytes in the pcap file
    	packetInitreqObj.setpropDataStructNestLevel(bufferReader.readUint8());
    	packetInitreqObj.setRandom(bufferReader.read(4)); // Reading unidentified bytes in the pcap file
    	packetInitreqObj.setpropVerNo(bufferReader.readUint8());
    	packetInitreqObj.setRandom(bufferReader.read(2)); // Reading unidentified bytes in the pcap file
    	packetInitreqObj.setpadding(bufferReader.readUint8());
    	packetInitreqObj.setpropParamCBB(bufferReader.readUint16());
    	packetInitreqObj.setRandom(bufferReader.read(2)); // Reading unidentified bytes in the pcap file
    	packetInitreqObj.setpadding(bufferReader.readUint8());
    	packetInitreqObj.setServSupportCalling(bufferReader.read(11));
    	
    	return packetInitreqObj;
    }
    
    public PacketSession02Obj parseSession02() throws Exception {
    	PacketSession02Obj packetSession02Obj = new PacketSession02Obj();
    	
    	packetSession02Obj.setSPDUtype(bufferReader.readUint8());
    	packetSession02Obj.setSession02Length(bufferReader.readUint8());
    	
    	return packetSession02Obj;
    }
    
    public Packet8823Obj1 parse8823_01() throws Exception {
    	Packet8823Obj1 packet8823Obj1 = new Packet8823Obj1();
    	
    	packet8823Obj1.setRandom(bufferReader.read(6)); 
    	packet8823Obj1.setcontext_identif(bufferReader.readUint8());
    	packet8823Obj1.setRandom(bufferReader.read(2));
    	
    	return packet8823Obj1;
    	
    }
    
    public MMSTypeIdentifier parsemmsType() throws Exception {
    	MMSTypeIdentifier mmsTypeObj = new MMSTypeIdentifier();
    	
    	mmsTypeObj.setmmsType(bufferReader.readUint8());
    	mmsTypeObj.setTLV_Len(bufferReader.readUint8());
    	
    	return mmsTypeObj;
    }
    
    public PacketConfirmReqObj parseConfirmReq() throws Exception {
    	PacketConfirmReqObj ConfirmReqObj = new PacketConfirmReqObj();
    	
    	ConfirmReqObj.setTLV(bufferReader.read(2));		//Read Tag and Length
    	ConfirmReqObj.setinvokeID(bufferReader.readUint8());
    	ConfirmReqObj.setReqType(bufferReader.readUint8());	
    	ConfirmReqObj.setTLV_Len(bufferReader.readUint8());	//Read the TLV length
    	int len = ConfirmReqObj.getTLV_Len();
    	if (len != 0){
    	ConfirmReqObj.setReqData(bufferReader.read(len));
    	}
    	return ConfirmReqObj;
    	
    }
    
    public PacketConfirmRespObj parseConfirmResp() throws Exception {
    	PacketConfirmRespObj ConfirmRespObj = new PacketConfirmRespObj();
    	
    	ConfirmRespObj.setTLV(bufferReader.read(2));		//Read Tag and Length
    	ConfirmRespObj.setinvokeID(bufferReader.readUint8());
    	if(bufferReader.remaining() != 0) {
    		ConfirmRespObj.setRespType(bufferReader.readUint8());	
    		ConfirmRespObj.setTLV_Len(bufferReader.readUint8());	//Read the TLV length
    		int len = ConfirmRespObj.getTLV_Len();
    		if (len != 0){
    			ConfirmRespObj.setRespData(bufferReader.read(len));
    		}
    	}
    	return ConfirmRespObj;
    	
    }

}    

