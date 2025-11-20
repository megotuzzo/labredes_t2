package com.example;

import com.opencsv.CSVWriter;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IcmpV4Packet;
import org.pcap4j.packet.IcmpV6Packet;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.namednumber.IpNumber;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@Command(name = "monitor", mixinStandardHelpOptions = true,
         description = "Monitor de tráfego em tempo real baseado em Pcap4J.")
public class Monitor implements Callable<Integer> {

    @CommandLine.Parameters(index = "0", description = "Interface de rede (ex.: eth0, enp4s0, wlan0)")
    private String interfaceName;

    @Option(names = {"--logs"}, description = "Pasta para salvar CSVs (padrão: diretório atual)", defaultValue = ".")
    private String logDirectory;

    @Option(names = {"--no-reset"}, description = "Não apagar CSVs antigos ao iniciar")
    private boolean noReset = false;

    // Constantes
    private static final int UI_REFRESH_MS = 1000;
    private static final int SOCKET_TIMEOUT_MS = 500; // Equivalente ao SOCKET_TIMEOUT_S
    private static final int SNAPSHOT_LENGTH = 65536; // Tamanho máximo do pacote

    // Portas de aplicação
    private static final Map<String, Set<Integer>> PORTAS_APP = Map.of(
            "HTTP", Set.of(80, 443),
            "DNS", Set.of(53),
            "DHCP", Set.of(67, 68),
            "NTP", Set.of(123)
    );

    // Formato de data/hora
    private static final DateTimeFormatter TS_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    // Contadores (usando AtomicLong para segurança em threads, embora aqui seja single-thread)
    private final Map<String, AtomicLong> count = new ConcurrentHashMap<>();

    // Gerenciador de CSV
    private CsvWriters csvWriters;

    // Referência ao PcapHandle para fechar no shutdown
    private volatile PcapHandle handle;

    /**
     * Classe interna para gerenciar a escrita de múltiplos arquivos CSV.
     */
    static class CsvWriters implements AutoCloseable {
        private final Path logDir;
        private final Map<String, String[]> headers = Map.of(
                "internet", new String[]{"Data/Hora", "Protocolo", "IP Origem", "IP Destino", "Protocolo Superior", "Tamanho"},
                "transporte", new String[]{"Data/Hora", "Protocolo", "IP Origem", "Porta Origem", "IP Destino", "Porta Destino", "Tamanho"},
                "aplicacao", new String[]{"Data/Hora", "Protocolo", "IP Origem", "IP Destino", "Tamanho"}
        );
        private final Map<String, CSVWriter> writers = new HashMap<>();
        private final Map<String, Boolean> needsHeader = new HashMap<>();

        public CsvWriters(String logDir, boolean reset) throws IOException {
            this.logDir = Paths.get(logDir);
            Files.createDirectories(this.logDir);

            for (String nome : headers.keySet()) {
                Path path = this.logDir.resolve(nome + ".csv");
                needsHeader.put(nome, true); // Assume que precisa de cabeçalho

                if (reset && Files.exists(path)) {
                    try {
                        Files.delete(path);
                    } catch (IOException e) {
                        System.err.println("Falha ao apagar CSV antigo: " + path);
                    }
                }

                if (Files.exists(path)) {
                    needsHeader.put(nome, false); // Arquivo já existe, não precisa de cabeçalho
                }
            }
        }

        public void writeRow(String nome, String[] row) {
            try {
                CSVWriter writer = writers.get(nome);
                if (writer == null) {
                    Path path = logDir.resolve(nome + ".csv");
                    Writer fileWriter = new FileWriter(path.toFile(), true); // Modo Append
                    writer = new CSVWriter(fileWriter);
                    writers.put(nome, writer);

                    if (needsHeader.get(nome)) {
                        writer.writeNext(headers.get(nome));
                        needsHeader.put(nome, false); // Cabeçalho escrito
                    }
                }
                writer.writeNext(row);
                writer.flush(); // Equivalente ao fp.flush() do Python
            } catch (IOException e) {
                System.err.println("Erro ao escrever no CSV " + nome + ": " + e.getMessage());
            }
        }

        @Override
        public void close() {
            for (CSVWriter writer : writers.values()) {
                try {
                    writer.close();
                } catch (IOException e) {
                    // Ignora
                }
            }
        }
    }

    /**
     * Ponto de entrada principal da lógica do monitor.
     */
    @Override
    public Integer call() throws Exception {
        // Inicializa contadores
        Arrays.asList("ipv4", "ipv6", "icmp", "tcp", "udp", "http", "dns", "dhcp", "ntp", "outros", "total")
                .forEach(k -> count.put(k, new AtomicLong(0)));

        // Inicializa CSVs
        this.csvWriters = new CsvWriters(logDirectory, !noReset);

        // Encontra a interface de rede
        PcapNetworkInterface nif;
        try {
            nif = Pcaps.getDevByName(interfaceName);
        } catch (Exception e) {
            System.err.println("[ERRO] Interface não encontrada: " + interfaceName);
            System.err.println("Interfaces disponíveis:");
            Pcaps.findAllDevs().forEach(dev -> System.err.println("- " + dev.getName()));
            return 1;
        }

        System.out.println("Ouvindo em: " + nif.getName());

        // Abre o PcapHandle (equivalente a abrir o socket raw)
        this.handle = nif.openLive(SNAPSHOT_LENGTH, PromiscuousMode.PROMISCUOUS, SOCKET_TIMEOUT_MS);

        // Hook para fechar o handle e os CSVs ao pressionar Ctrl+C
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            if (handle != null && handle.isOpen()) {
                try {
                    handle.breakLoop(); // Para o loop de captura
                } catch (NotOpenException e) {
                    // Ignora
                }
                handle.close();
            }
            if (csvWriters != null) {
                csvWriters.close();
            }
            System.out.println("\nMonitoramento encerrado.");
        }));

        long ultimoUi = 0;
        renderUi(); // Renderiza a UI inicial

        // Loop de captura
        while (handle.isOpen()) {
            Packet packet;
            try {
                // Tenta pegar o próximo pacote. Retorna null se o timeout ocorrer.
                packet = handle.getNextPacket();
            } catch (NotOpenException e) {
                // O handle foi fechado (provavelmente pelo shutdown hook)
                break;
            }

            if (packet != null) {
                // Pacote recebido, processa
                count.get("total").incrementAndGet();
                processPacket(packet);
            }

            // Lógica de atualização da UI (ocorre mesmo se packet == null)
            long agora = System.currentTimeMillis();
            if (agora - ultimoUi >= UI_REFRESH_MS) {
                renderUi();
                ultimoUi = agora;
            }
        }
        return 0;
    }

    /**
     * Processa um pacote capturado.
     */
    private void processPacket(Packet packet) {
        // Pcap4J faz o parse automaticamente. Apenas pegamos as partes que queremos.

        IpV4Packet ipV4 = packet.get(IpV4Packet.class);
        IpV6Packet ipV6 = packet.get(IpV6Packet.class);

        if (ipV4 != null) {
            count.get("ipv4").incrementAndGet();
            IpV4Packet.IpV4Header hdr = ipV4.getHeader();
            String srcIp = hdr.getSrcAddr().getHostAddress();
            String dstIp = hdr.getDstAddr().getHostAddress();
            String tam = String.valueOf(hdr.getTotalLengthAsInt());
            IpNumber protoNum = hdr.getProtocol();

            if (protoNum.equals(IpNumber.ICMPV4)) {
                count.get("icmp").incrementAndGet();
                csvWriters.writeRow("internet", new String[]{ts(), "ICMP", srcIp, dstIp, "", tam});
            } else {
                csvWriters.writeRow("internet", new String[]{ts(), "IPv4", srcIp, dstIp, protoNum.name(), tam});
                if (protoNum.equals(IpNumber.TCP)) {
                    count.get("tcp").incrementAndGet();
                    TcpPacket tcp = packet.get(TcpPacket.class);
                    if (tcp != null) {
                        String sp = tcp.getHeader().getSrcPort().valueAsString();
                        String dp = tcp.getHeader().getDstPort().valueAsString();
                        csvWriters.writeRow("transporte", new String[]{ts(), "TCP", srcIp, sp, dstIp, dp, tam});
                        classificarAplicacao("TCP", srcIp, tcp.getHeader().getSrcPort().value(), dstIp, tcp.getHeader().getDstPort().value(), tam);
                    }
                } else if (protoNum.equals(IpNumber.UDP)) {
                    count.get("udp").incrementAndGet();
                    UdpPacket udp = packet.get(UdpPacket.class);
                    if (udp != null) {
                        String sp = udp.getHeader().getSrcPort().valueAsString();
                        String dp = udp.getHeader().getDstPort().valueAsString();
                        csvWriters.writeRow("transporte", new String[]{ts(), "UDP", srcIp, sp, dstIp, dp, tam});
                        classificarAplicacao("UDP", srcIp, udp.getHeader().getSrcPort().value(), dstIp, udp.getHeader().getDstPort().value(), tam);
                    }
                } else {
                    count.get("outros").incrementAndGet();
                }
            }
        } else if (ipV6 != null) {
            count.get("ipv6").incrementAndGet();
            IpV6Packet.IpV6Header hdr = ipV6.getHeader();
            String srcIp = hdr.getSrcAddr().getHostAddress();
            String dstIp = hdr.getDstAddr().getHostAddress();
            String tam = String.valueOf(hdr.getPayloadLengthAsInt() + 40); // 40 bytes de cabeçalho v6
            IpNumber protoNum = hdr.getNextHeader();

            if (protoNum.equals(IpNumber.ICMPV6)) {
                count.get("icmp").incrementAndGet();
                csvWriters.writeRow("internet", new String[]{ts(), "ICMP", srcIp, dstIp, "", tam});
            } else {
                csvWriters.writeRow("internet", new String[]{ts(), "IPv6", srcIp, dstIp, protoNum.name(), tam});
                if (protoNum.equals(IpNumber.TCP)) {
                    count.get("tcp").incrementAndGet();
                    TcpPacket tcp = packet.get(TcpPacket.class);
                    if (tcp != null) {
                        String sp = tcp.getHeader().getSrcPort().valueAsString();
                        String dp = tcp.getHeader().getDstPort().valueAsString();
                        csvWriters.writeRow("transporte", new String[]{ts(), "TCP", srcIp, sp, dstIp, dp, tam});
                        classificarAplicacao("TCP", srcIp, tcp.getHeader().getSrcPort().value(), dstIp, tcp.getHeader().getDstPort().value(), tam);
                    }
                } else if (protoNum.equals(IpNumber.UDP)) {
                    count.get("udp").incrementAndGet();
                    UdpPacket udp = packet.get(UdpPacket.class);
                    if (udp != null) {
                        String sp = udp.getHeader().getSrcPort().valueAsString();
                        String dp = udp.getHeader().getDstPort().valueAsString();
                        csvWriters.writeRow("transporte", new String[]{ts(), "UDP", srcIp, sp, dstIp, dp, tam});
                        classificarAplicacao("UDP", srcIp, udp.getHeader().getSrcPort().value(), dstIp, udp.getHeader().getDstPort().value(), tam);
                    }
                } else {
                    count.get("outros").incrementAndGet();
                }
            }
        } else {
            // Outros pacotes (ex: ARP, etc.)
            count.get("outros").incrementAndGet();
        }
    }

    /**
     * Classifica a aplicação com base no protocolo e portas.
     */
    private void classificarAplicacao(String proto, String srcIp, int sp, String dstIp, int dp, String tam) {
        // Função auxiliar
        java.util.function.Predicate<String> bate = (app) ->
                PORTAS_APP.get(app).contains(sp) || PORTAS_APP.get(app).contains(dp);

        if (proto.equals("TCP") && bate.test("HTTP")) {
            count.get("http").incrementAndGet();
            csvWriters.writeRow("aplicacao", new String[]{ts(), "HTTP", srcIp, dstIp, tam});
        } else if (proto.equals("UDP")) {
            for (String nome : Arrays.asList("DNS", "DHCP", "NTP")) {
                if (bate.test(nome)) {
                    count.get(nome.toLowerCase()).incrementAndGet();
                    csvWriters.writeRow("aplicacao", new String[]{ts(), nome, srcIp, dstIp, tam});
                    break; // Um pacote UDP não será DNS e DHCP ao mesmo tempo
                }
            }
        }
    }

    /**
     * Limpa a tela e renderiza a UI de estatísticas.
     */
    private void renderUi() {
        clearScreen();
        String line = "═".repeat(52);
        String dottedLine = "·".repeat(54);
        String solidLine = "─".repeat(54);

        System.out.println("╔" + line + "╗");
        System.out.printf("║%52s║%n", "MONITOR DE TRÁFEGO");
        System.out.println("╚" + line + "╝");
        System.out.println("Interface: " + interfaceName);
        System.out.println(solidLine);

        // Seção
        System.out.println("\n[ REDE ]");
        System.out.println(dottedLine);
        System.out.printf("IPv4: %-6d IPv6: %-6d ICMP: %-6d%n",
                count.get("ipv4").get(), count.get("ipv6").get(), count.get("icmp").get());
        System.out.println();

        // Seção
        System.out.println("[ TRANSPORTE ]");
        System.out.println(dottedLine);
        System.out.printf("TCP: %-6d UDP: %-6d%n",
                count.get("tcp").get(), count.get("udp").get());
        System.out.println();

        // Seção
        System.out.println("[ APLICAÇÃO ]");
        System.out.println(dottedLine);
        System.out.printf("HTTP: %-6d DNS: %-6d DHCP: %-6d NTP: %-6d%n",
                count.get("http").get(), count.get("dns").get(), count.get("dhcp").get(), count.get("ntp").get());
        System.out.println();

        // Seção
        System.out.println("[ TOTAL ]");
        System.out.println(dottedLine);
        System.out.printf("Pacotes: %-6d Outros: %-6d%n",
                count.get("total").get(), count.get("outros").get());
        System.out.println();

        System.out.println(solidLine);
        System.out.flush();
    }

    /**
     * Limpa o console.
     */
    private void clearScreen() {
        try {
            if (System.getProperty("os.name").contains("Windows")) {
                new ProcessBuilder("cmd", "/c", "cls").inheritIO().start().waitFor();
            } else {
                // Assume ANSI (Linux, macOS)
                System.out.print("\033[H\033[2J");
                System.out.flush();
            }
        } catch (IOException | InterruptedException e) {
            // Se falhar, apenas imprime novas linhas
            System.out.println("\n".repeat(50));
        }
    }

    /**
     * Retorna o timestamp atual formatado.
     */
    private String ts() {
        return LocalDateTime.now().format(TS_FORMATTER);
    }

    /**
     * Ponto de entrada da aplicação.
     */
    public static void main(String[] args) {
        // Picocli cuida do parse dos args e chama o método call()
        int exitCode = new CommandLine(new Monitor()).execute(args);
        System.exit(exitCode);
    }
}