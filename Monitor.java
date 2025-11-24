import java.util.*;

public class Monitor {

    private volatile boolean running = true;

    private final RawPacketReader reader;
    private final PacketParser parser = new PacketParser();
    private final CsvLogger csv;

    // Contadores
    private final Map<String, Long> counters = new HashMap<>();

    public Monitor() throws Exception { //le o socket desenvolvido em C
        this.reader = new RawPacketReader("./raw_socket");
        this.csv = new CsvLogger(".");

        initCounters();
    }

    private void initCounters() {
        counters.put("total", 0L);
        counters.put("ipv4", 0L);
        counters.put("ipv6", 0L);

        counters.put("tcp", 0L);
        counters.put("udp", 0L);
        counters.put("icmp", 0L);
        counters.put("outros", 0L);

        counters.put("http", 0L);
        counters.put("https", 0L);
        counters.put("dns", 0L);
        counters.put("dhcp", 0L);
        counters.put("ntp", 0L);
    }

    public static void main(String[] args) throws Exception {
        new Monitor().run();
    }

    private void run() throws Exception {

        System.out.println("Iniciando Monitor de Tráfego.");

        long lastPrint = System.currentTimeMillis();

        while (running) {

            RawPacketReader.PacketData pd = reader.readPacket();
            if (pd == null)
                continue;

            counters.put("total", counters.get("total") + 1);

            PacketParser.ParsedPacket p = parser.parse(pd.data);
            if (p == null)
                continue;

            // internet
            if ("IPv4".equals(p.layer))
                counters.put("ipv4", counters.get("ipv4") + 1);
            else if ("IPv6".equals(p.layer))
                counters.put("ipv6", counters.get("ipv6") + 1);

            csv.logInternet(p);

            // transprte
            if (p.transport != null) {

                switch (p.transport) {
                    case "TCP":
                        counters.put("tcp", counters.get("tcp") + 1);
                        break;

                    case "UDP":
                        counters.put("udp", counters.get("udp") + 1);
                        break;

                    case "ICMP":
                        counters.put("icmp", counters.get("icmp") + 1);
                    case "ICMPv6":
                        counters.put("icmp", counters.get("icmp") + 1);
                        break;

                    default:
                        counters.put("outros", counters.get("outros") + 1);
                }
            }

            csv.logTransporte(p);

            // Aplicacao
            if (p.application != null) {
                switch (p.application) {
                    case "HTTP":
                        counters.put("http", counters.get("http") + 1);
                        break;
                    case "HTTPS":
                        counters.put("https", counters.get("https") + 1);
                        break;
                    case "DNS":
                        counters.put("dns", counters.get("dns") + 1);
                        break;
                    case "DHCP":
                        counters.put("dhcp", counters.get("dhcp") + 1);
                        break;
                    case "NTP":
                        counters.put("ntp", counters.get("ntp") + 1);
                        break;
                }

                csv.logAplicacao(p);
            }

            // imprime a cada segundo
            long now = System.currentTimeMillis();
            if (now - lastPrint >= 1000) {
                printStats();
                lastPrint = now;
            }
        }
    }

    private void printStats() {
        System.out.println("\n========== ESTATÍSTICAS ==========");
        System.out.println("Total de pacotes: " + counters.get("total"));

        System.out.println("\n--- Camada Internet ---");
        System.out.println("IPv4: " + counters.get("ipv4"));
        System.out.println("IPv6: " + counters.get("ipv6"));

        System.out.println("\n--- Camada Transporte ---");
        System.out.println("TCP:  " + counters.get("tcp"));
        System.out.println("UDP:  " + counters.get("udp"));
        System.out.println("ICMP: " + counters.get("icmp"));

        System.out.println("\n--- Camada Aplicação ---");
        System.out.println("HTTP: " + counters.get("http"));
        System.out.println("HTTPS: " + counters.get("https"));
        System.out.println("DNS: " + counters.get("dns"));
        System.out.println("DHCP: " + counters.get("dhcp"));
        System.out.println("NTP: " + counters.get("ntp"));

        System.out.println("===================================\n");
    }
}
