
import java.util.*;

public class Monitor {

    private volatile boolean running = true;

    private final RawPacketReader reader;
    private final PacketParser parser = new PacketParser();
    private final CsvLogger csv;

    private final Map<String, Long> counters = new HashMap<>();

    public Monitor() throws Exception {
        this.reader = new RawPacketReader("./raw_socket");
        this.csv = new CsvLogger(".");

        counters.put("total", 0L);
        counters.put("ipv4", 0L);
        counters.put("ipv6", 0L);
        counters.put("tcp", 0L);
        counters.put("udp", 0L);
        counters.put("icmp", 0L);
        counters.put("outros", 0L);
    }

    public static void main(String[] args) throws Exception {
        Monitor m = new Monitor();
        m.run();
    }

    private void run() throws Exception {
        while (running) {
            RawPacketReader.PacketData pd = reader.readPacket();
            if (pd == null)
                continue;

            counters.put("total", counters.get("total") + 1);

            PacketParser.ParsedPacket p = parser.parse(pd.data);
            if (p == null)
                continue;

            if (p.protocol.equals("TCP"))
                counters.put("tcp", counters.get("tcp") + 1);
            else if (p.protocol.equals("UDP"))
                counters.put("udp", counters.get("udp") + 1);
            else if (p.protocol.equals("ICMP") || p.protocol.equals("ICMPv6"))
                counters.put("icmp", counters.get("icmp") + 1);

            csv.logInternet(p);
            csv.logTransporte(p);
        }
    }
}
