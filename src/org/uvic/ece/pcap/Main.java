package org.uvic.ece.pcap;

import org.uvic.ece.pcap.obj.*;
import org.uvic.ece.pcap.reader.GlobalHeaderReader;
import org.uvic.ece.pcap.reader.PacketDataReader;
import org.uvic.ece.pcap.reader.PacketHeaderReader;
import org.uvic.ece.pcap.reader.buffer.BufferReader;
import org.uvic.ece.pcap.reader.file.FileReader;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;


public class Main {


	public static FileInputStream fileInputStream;
	


	public static void main(String[] args) throws Exception {

		try {
			writeCsvHeader();
			
			fileInputStream = new FileInputStream(new File("/Users/shivam/Meng project/iec_61850_reader/IEC61850_write_messages-01.pcap"));
			System.out.println("Input File: " + fileInputStream);
			
			GlobalHeaderReader globalHeaderReader = new GlobalHeaderReader(fileInputStream);
			GlobalHeaderObj globalHeaderObj = globalHeaderReader.read();
			System.out.println("Global Header object: " + globalHeaderObj);

			if (GlobalHeaderObj.NETWORK_ETHERNET != globalHeaderObj.getNetwork()){
				System.out.println("gdfgbdfbg");
				return;
			}

			FileReader fileReader = new FileReader(fileInputStream, globalHeaderObj.isSwapped());
			PacketHeaderReader packetHeaderReader = new PacketHeaderReader(fileReader);
			int num = 0;
			
			while (true) {
				num++;
				try {
					// read packet header
					PacketHeaderObj packetHeaderObj = packetHeaderReader.read();

					// read packet body
					byte[] data = fileReader.read((int) packetHeaderObj.getInclLen());
					if (packetHeaderObj.getInclLen() != packetHeaderObj.getOrigLen()) {
						System.err.println("Packet No." + num + ", the original packet was limited");
						continue;
					}

					// parse body
					try {
						
						parseBody(num, data);
					} catch (Exception e) {
						System.err.println("Packet No." + num + ", exception occurs, message = " + e.getClass());
					}
				} catch (Exception e) {
					e.printStackTrace();
					break;
				}
			}
		} finally {
			if (null != fileInputStream)
				fileInputStream.close();
		}
	}

	private static void parseBody(int num, byte[] data) throws Exception {
		
		
		// prepare for parsing
		BufferReader bufferReader = new BufferReader(data, true);
		PacketDataReader packetDataReader = new PacketDataReader(bufferReader);

		// parse ethernet header
		PacketEthernetObj packetEthernetObj = packetDataReader.parseEthernet();
		if (PacketEthernetObj.TYPE_IPV4 != packetEthernetObj.getType())
			return;

		// parse ipv4 header
		PacketIpv4Obj packetIpv4Obj = packetDataReader.parseIpv4();
		if (PacketIpv4Obj.TYPE_IPV4 != packetIpv4Obj.getType())
			return;
		if (PacketIpv4Obj.PROTOCOL_TCP != packetIpv4Obj.getProtocol())
			return;
		if (PacketIpv4Obj.HEADER_LENGTH != packetIpv4Obj.getHeaderLength()) {
			System.err.println("Packet No." + num + ", the ipv4 data was wrong");
			return;
		} else if (packetIpv4Obj.getTotalLength() + PacketEthernetObj.PACKET_LENGTH != data.length) {
			//System.err.println("Packet No." + num + ", the packet length does not match");
			return;
		}

		 
		// parse tcp header
		PacketTcpObj packetTcpObj = packetDataReader.parseTcp();
		while (bufferReader.hasRemaining()) {
			if (bufferReader.remaining() <= 8)
				return;

			//parse Tpkt header
			PacketTpktObj packetTpktObj = packetDataReader.parseTpkt();

			if(bufferReader.remaining() != (packetTpktObj.getTpktLength() - 4))
				return;

			//parse Cotp header
			PacketCotpObj packetCotpObj = packetDataReader.parseCotp();

			if(packetCotpObj.getCotpLength() != 2)
				return;

			//parse ISO-8327-1 Session layer Protocol 1st
			PacketSession01Obj packetSession01Obj = packetDataReader.parseSession01();

			
			
			if((packetSession01Obj.getSPDUtype() == 13) | (packetSession01Obj.getSPDUtype() == 14)){ //Check if the SPDU type is Connect or not for initiate request / response PDU.

				//parse remaining part of session layer protocol for initiate request PDU
				PacketSession01RemainingObj packetSession01RemainingObj = packetDataReader.parseSession01Remaining();

				// parse presentation layer protocol
				Packet8823Obj packet8823Obj = packetDataReader.parse8823();

				//parse association control service (ISO 8650 -1)
				Packet8650Obj packet8650Obj = packetDataReader.parse8650();

				// Check type of MMS PDU [initiate request and response] 
				MMSTypeIdentifier mmsType = packetDataReader.parsemmsType();

				if((mmsType.getmmsType() & 0x0F) == 8) {
					//parse initiate request pdu
					PacketInitreqObj packetInitreqObj = packetDataReader.parseInitreq();

					int[] ipv4_source = packetIpv4Obj.getSource();
					int[] ipv4_dest = packetIpv4Obj.getDest();
					int tcp_sourceport = packetTcpObj.getSourcePort();
					int tcp_destport = packetTcpObj.getDestPort();
					int LocalDetailCalling = packetInitreqObj.getLocalDetailCalling();
					int propMaxServOutCalling = packetInitreqObj.getpropMaxServOutCalling();
					int propMaxServOutCalled = packetInitreqObj.getpropMaxServOutCalled();
					int propDataStructNestLevel = packetInitreqObj.getpropDataStructNestLevel();
					int propVerNo = packetInitreqObj.getpropVerNo();
					int propParamCBB = packetInitreqObj.getpropParamCBB();
					String CBBparam = Integer.toHexString(propParamCBB);           
					
					CsvDataCollector packet1 = new CsvDataCollector(ipv4_source, ipv4_dest, tcp_sourceport, tcp_destport);
					
					writepackets(packet1);
					
					System.out.printf("\"%d\",\"%d.%d.%d.%d\",\"%d.%d.%d.%d\",\"%d\",\"%d\",\"%d\",\"%d\",\"%d\",\"%d\",\"%d\",\"%s\"\n",
							num, ipv4_source[0], ipv4_source[1], ipv4_source[2], ipv4_source[3], ipv4_dest[0], ipv4_dest[1], ipv4_dest[2], ipv4_dest[3],
							tcp_sourceport,tcp_destport,LocalDetailCalling,propMaxServOutCalling,propMaxServOutCalled,propDataStructNestLevel, propVerNo,CBBparam);

				} else if ((mmsType.getmmsType() & 0x0F) == 0x09) {
					//parse initiate response pdu
				}
			}
			else {

				//parse ISO-8327-1 Session layer Protocol 2nd
				PacketSession02Obj packetSession02Obj = packetDataReader.parseSession02();

				// parse ISO 8823 presentation layer protocol 2nd
				Packet8823Obj1 packet8823Obj1 = packetDataReader.parse8823_01();

				// Check type of MMS PDU [other than initiate request and response] 
				MMSTypeIdentifier mmstype = packetDataReader.parsemmsType();

				if ((mmstype.getmmsType() & 0x0F) == 0x00) {
					//parse confirmed request PDU
					//System.out.println("Parsing the confirm request PDU");
					PacketConfirmReqObj packetConfirmReqObj = packetDataReader.parseConfirmReq();

					int[] ipv4_source = packetIpv4Obj.getSource();
					int[] ipv4_dest = packetIpv4Obj.getDest();
					int tcp_sourceport = packetTcpObj.getSourcePort();
					int tcp_destport = packetTcpObj.getDestPort();
					int invokeID = packetConfirmReqObj.getinvokeID();
					int ReqType = packetConfirmReqObj.getReqType();
					String req = Integer.toHexString(ReqType);

					//FileWriter filewriter2 = new FileWriter("/Users/shivam/Extracted_data2.csv");
					CsvDataCollector packet2 = new CsvDataCollector(ipv4_source, ipv4_dest, tcp_sourceport, tcp_destport);
					
					writepackets(packet2);
					//filewriter2.close();
					
					System.out.printf("\"%d\",\"%d.%d.%d.%d\",\"%d.%d.%d.%d\",\"%d\",\"%d\",\"%d\",\"%s\"\n",num, ipv4_source[0], ipv4_source[1], ipv4_source[2], ipv4_source[3],
							ipv4_dest[0], ipv4_dest[1], ipv4_dest[2], ipv4_dest[3], tcp_sourceport, tcp_destport,invokeID,req);

				} else if ((mmstype.getmmsType() & 0x0F) == 0x01) {
					//parse confirmed response PDU
					//System.out.println("Parsing the confirm response PDU");
					PacketConfirmRespObj packetConfirmRespObj = packetDataReader.parseConfirmResp();

					int[] ipv4_source = packetIpv4Obj.getSource();
					int[] ipv4_dest = packetIpv4Obj.getDest();
					int tcp_sourceport = packetTcpObj.getSourcePort();
					int tcp_destport = packetTcpObj.getDestPort();
					int invokeID = packetConfirmRespObj.getinvokeID();
					int RespType = packetConfirmRespObj.getRespType();
					String respType = Integer.toHexString(RespType);
					

					System.out.printf("\"%d\",\"%d.%d.%d.%d\",\"%d.%d.%d.%d\",\"%d\",\"%d\",\"%d\",\"%s\"\n",num, ipv4_source[0], ipv4_source[1], ipv4_source[2], ipv4_source[3],
							ipv4_dest[0], ipv4_dest[1], ipv4_dest[2], ipv4_dest[3], tcp_sourceport, tcp_destport,invokeID, respType);
					
					
	
					CsvDataCollector packet3 = new CsvDataCollector(ipv4_source, ipv4_dest, tcp_sourceport, tcp_destport);
					writepackets(packet3);
					

				} else if ((mmstype.getmmsType() & 0x0F) == 0x02) {
					//parse confirmed-error PDU
				} else if ((mmstype.getmmsType() & 0x0F) == 0x03){
					// parse unconfirmed PDU
				}else if ((mmstype.getmmsType() & 0x0F) == 0x04){
					// parse reject PDU
				}else if ((mmstype.getmmsType() & 0x0F) == 0x05){
					// parse cancel-request PDU
				}else if ((mmstype.getmmsType() & 0x0F) == 0x06){
					// parse cancel-response PDU
				}else if ((mmstype.getmmsType() & 0x0F) == 0x07){
					// parse cancel-Error PDU
				}else if ((mmstype.getmmsType() & 0x0F) == 0x0A){
					// parse initiate error PDU
				}else if ((mmstype.getmmsType() & 0x0F) == 0x0B){
					// parse conclude request PDU
				}else if ((mmstype.getmmsType() & 0x0F) == 0x0C){
					// parse conclude response PDU
				}else{
					// parse conclude error PDU 
				}		
				
			}			  
				
			}
		}
	
	private static void writeCsvHeader() {
		try {
			FileWriter fileWriter = new FileWriter("/Users/shivam/data1.csv");
			fileWriter.append("\"sourceIP\",\"DestIP\",\"SourcePort\",\"destPort\"");
			fileWriter.append("\n");
			fileWriter.flush();
			fileWriter.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block	
			e.printStackTrace();
		}
	}

	private static void writepackets(CsvDataCollector packet) {
		// TODO Auto-generated method stub
		try {
			FileWriter fileWriter = new FileWriter("/Users/shivam/data1.csv", true);
			fileWriter.append(String.valueOf(packet));
			fileWriter.append("\n");
			fileWriter.flush();
			fileWriter.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		
	}
}
