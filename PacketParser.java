import java.text.SimpleDateFormat;
import java.util.Date;

public class PacketParser {

    private final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");

    public ParsedPacket parse(byte[] pkt) {

        // Ethernet header = 14 bytes
        if (pkt.length < 14) {
            return null;
        }

        int etherType = u16(pkt, 12);

        if (etherType == 0x0800) {
            return parseIPv4(pkt, 14);

        }
        if (etherType == 0x86DD) {
            return parseIPv6(pkt, 14);
        }
        return null;
    }

    private ParsedPacket parseIPv4(byte[] pkt, int off) {

        if (pkt.length < off + 20) {
            return null;
        }

        int ihl = (pkt[off] & 0x0F) * 4;
        int proto = pkt[off + 9] & 0xFF;
        int totalLen = u16(pkt, off + 2);

        ParsedPacket p = new ParsedPacket();
        p.timestamp = sdf.format(new Date());
        p.layer = "IPv4";
        p.protoNumber = proto;

        p.src = ipv4(pkt, off + 12);
        p.dst = ipv4(pkt, off + 16);
        p.totalBytes = totalLen;

        int payloadOffset = off + ihl;

        switch (proto) {
            case 6:  // TCP
                if (pkt.length >= payloadOffset + 20) {
                    parseTCP(pkt, payloadOffset, p);
                }
                break;
            case 17: // UDP
                if (pkt.length >= payloadOffset + 8) {
                    parseUDP(pkt, payloadOffset, p);
                }
                break;
            case 1:  // ICMP
                parseICMP(pkt, payloadOffset, p);
                break;
            default:
                p.protocol = "outro";
        }

        return p;
    }

    private ParsedPacket parseIPv6(byte[] pkt, int off) {

        if (pkt.length < off + 40) {
            return null;
        }

        int proto = pkt[off + 6] & 0xFF;
        int payloadLen = u16(pkt, off + 4);

        ParsedPacket p = new ParsedPacket();
        p.timestamp = sdf.format(new Date());
        p.layer = "IPv6";
        p.protoNumber = proto;

        p.src = ipv6(pkt, off + 8);
        p.dst = ipv6(pkt, off + 24);
        p.totalBytes = payloadLen + 40;

        int payloadOffset = off + 40;

        switch (proto) {
            case 6: // TCP
                if (pkt.length >= payloadOffset + 20) {
                    parseTCP(pkt, payloadOffset, p);
                }
                break;
            case 17: // UDP
                if (pkt.length >= payloadOffset + 8) {
                    parseUDP(pkt, payloadOffset, p);
                }
                break;
            case 58: // ICMPv6
                p.transport = "ICMPv6";
                p.protocol = "ICMPv6";
                break;
        }

        return p;
    }

    private void parseTCP(byte[] pkt, int off, ParsedPacket p) {
        p.transport = "TCP";
        p.protocol = "TCP";

        p.sport = u16(pkt, off);
        p.dport = u16(pkt, off + 2);

        // Aplicação por número de porta
        int appPort = (p.sport != 0) ? p.sport : p.dport;
        p.application = guessApplication(appPort);
    }

    private void parseUDP(byte[] pkt, int off, ParsedPacket p) {
        p.transport = "UDP";
        p.protocol = "UDP";

        p.sport = u16(pkt, off);
        p.dport = u16(pkt, off + 2);

        int appPort = (p.sport != 0) ? p.sport : p.dport;
        p.application = guessApplication(appPort);
    }

    private void parseICMP(byte[] pkt, int off, ParsedPacket p) {
        p.transport = "ICMP";
        p.protocol = "ICMP";

        if (pkt.length >= off + 2) {
            int type = pkt[off] & 0xFF;
            int code = pkt[off + 1] & 0xFF;
            p.icmpInfo = "type=" + type + ",code=" + code;
        }
    }


    private int u16(byte[] b, int off) {
        return ((b[off] & 0xFF) << 8) | (b[off + 1] & 0xFF);
    }

    private String ipv4(byte[] b, int off) {
        return (b[off] & 0xFF) + "." + (b[off + 1] & 0xFF) + "."
                + (b[off + 2] & 0xFF) + "." + (b[off + 3] & 0xFF);
    }

    private String ipv6(byte[] b, int off) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 16; i += 2) {
            int part = u16(b, off + i);
            sb.append(Integer.toHexString(part));
            if (i < 14)
                sb.append(":");
        }
        return sb.toString();
    }

    private String guessApplication(int port) {
        switch (port) {
            case 80:
                return "HTTP";
            case 443:
                return "HTTPS";
            case 53:
                return "DNS";
            case 67:
                return "DHCP";
            case 68:
                return "DHCP";
            case 123:
                return "NTP";
            default:
                return "desconhecido";
        }
    }

    public static class ParsedPacket {

        public String timestamp;

        public String layer;        // IPv4 ou IPv6
        public int protoNumber;     // 6, 17, 1 etc

        public String src, dst;
        public String protocol;
        public String transport;

        public int sport = -1, dport = -1;

        public int totalBytes;
        public String application;

        public String icmpInfo;     // type/code
    }
}
