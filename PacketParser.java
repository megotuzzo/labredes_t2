import java.text.SimpleDateFormat;
import java.util.*;

public class PacketParser {
    private final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");

    public ParsedPacket parse(byte[] pkt) {
        if (pkt.length < 14) return null;
        int etherType = ((pkt[12] & 0xFF) << 8) | (pkt[13] & 0xFF);

        if (etherType == 0x0800) return parseIPv4(pkt, 14);
        if (etherType == 0x86DD) return parseIPv6(pkt, 14);
        return null;
    }

    private ParsedPacket parseIPv4(byte[] pkt, int offset) {
        if (pkt.length < offset + 20) return null;
        int ihl = (pkt[offset] & 0x0F) * 4;
        int totalLen = ((pkt[offset+2]&0xFF)<<8) | (pkt[offset+3]&0xFF);
        int proto = pkt[offset+9] & 0xFF;

        String src = ipv4(pkt, offset+12);
        String dst = ipv4(pkt, offset+16);

        ParsedPacket p = new ParsedPacket();
        p.timestamp = sdf.format(new Date());
        p.src = src;
        p.dst = dst;
        p.totalBytes = totalLen;
        p.protocol = protoName(proto);

        int payloadOffset = offset + ihl;
        if (proto == 6 && pkt.length >= payloadOffset + 20) parseTCP(pkt, payloadOffset, p);
        else if (proto == 17 && pkt.length >= payloadOffset + 8) parseUDP(pkt, payloadOffset, p);
        else if (proto == 1) p.transport = "ICMP";

        return p;
    }

    private ParsedPacket parseIPv6(byte[] pkt, int offset) {
        if (pkt.length < offset + 40) return null;
        int proto = pkt[offset+6] & 0xFF;
        int payloadLen = ((pkt[offset+4]&0xFF)<<8)|(pkt[offset+5]&0xFF);

        ParsedPacket p = new ParsedPacket();
        p.timestamp = sdf.format(new Date());
        p.src = ipv6(pkt, offset+8);
        p.dst = ipv6(pkt, offset+24);
        p.totalBytes = payloadLen + 40;
        p.protocol = protoName(proto);

        int payloadOffset = offset + 40;
        if (proto == 6 && pkt.length >= payloadOffset + 20) parseTCP(pkt, payloadOffset, p);
        else if (proto == 17 && pkt.length >= payloadOffset + 8) parseUDP(pkt, payloadOffset, p);
        else if (proto == 58) p.transport = "ICMPv6";

        return p;
    }

    private void parseTCP(byte[] pkt, int off, ParsedPacket p) {
        p.transport = "TCP";
        p.sport = u16(pkt, off);
        p.dport = u16(pkt, off+2);
    }

    private void parseUDP(byte[] pkt, int off, ParsedPacket p) {
        p.transport = "UDP";
        p.sport = u16(pkt, off);
        p.dport = u16(pkt, off+2);
    }

    private int u16(byte[] b, int off) {
        return ((b[off]&0xFF)<<8)|(b[off+1]&0xFF);
    }

    private String ipv4(byte[] b, int off) {
        return (b[off]&0xFF)+"."+(b[off+1]&0xFF)+"."+(b[off+2]&0xFF)+"."+(b[off+3]&0xFF);
    }

    private String ipv6(byte[] b, int off) {
        StringBuilder sb = new StringBuilder();
        for (int i=0;i<16;i+=2){
            int part = ((b[off+i]&0xFF)<<8)|(b[off+i+1]&0xFF);
            sb.append(Integer.toHexString(part));
            if (i<14) sb.append(":");
        }
        return sb.toString();
    }

    private String protoName(int p) {
        switch (p){
            case 1: return "ICMP";
            case 6: return "TCP";
            case 17: return "UDP";
            default: return "outro";
        }
    }

    public static class ParsedPacket {
        public String timestamp;
        public String src, dst;
        public String protocol;
        public String transport;
        public int sport=-1, dport=-1;
        public int totalBytes;
    }
}
