import java.io.*;
import java.nio.charset.StandardCharsets;

public class CsvLogger {

    private final File internet;
    private final File transporte;
    private final File aplicacao;

    private final Object lockInet = new Object();
    private final Object lockTransp = new Object();
    private final Object lockApp = new Object();

    public CsvLogger(String basePath) throws IOException {
        this.internet = new File(basePath, "camada_internet.csv");
        this.transporte = new File(basePath, "camada_transporte.csv");
        this.aplicacao = new File(basePath, "camada_aplicacao.csv");

        // escreve os cabeçalhos se os arquivos nao existirem/esitverem vazio
        writeHeaderIfNeeded(internet,
                "timestamp,protocolo,ip_origem,ip_destino,proto_num,info_extra,tamanho_bytes\n");

        writeHeaderIfNeeded(transporte,
                "timestamp,protocolo,ip_origem,porta_origem,ip_destino,porta_destino,tamanho_bytes\n");

        writeHeaderIfNeeded(aplicacao,
                "timestamp,protocolo,info\n");
    }


    public void logInternet(PacketParser.ParsedPacket p) {

        String protoName;

        if (p.layer != null && p.layer.equals("IPv4")) {
            protoName = "IPv4";
        } else if (p.layer != null && p.layer.equals("IPv6")) {
            protoName = "IPv6";
        } else {
            protoName = p.protocol;
        }
        // para ICMP type/code
        String infoICMP = (p.icmpInfo == null ? "-" : p.icmpInfo);

        String line = String.join(",",
                quote(p.timestamp),
                protoName,
                p.src,
                p.dst,
                String.valueOf(p.protoNumber),
                quote(infoICMP),
                String.valueOf(p.totalBytes)
        ) + "\n";

        append(internet, lockInet, line);
    }

    public void logTransporte(PacketParser.ParsedPacket p) {

        String transport = (p.transport == null ? "-" : p.transport);

        String line = String.join(",",
                quote(p.timestamp),
                transport,
                p.src,
                (p.sport < 0 ? "-" : String.valueOf(p.sport)),
                p.dst,
                (p.dport < 0 ? "-" : String.valueOf(p.dport)),
                String.valueOf(p.totalBytes)
        ) + "\n";

        append(transporte, lockTransp, line);
    }

    public void logAplicacao(PacketParser.ParsedPacket p) {

        //if (p.application == null || p.application.equals("desconhecido")) {
        //    return; //n loga as desconhecidas
        //}
        String info = p.src + ":" + p.sport + " -> " + p.dst + ":" + p.dport;

        String line = String.join(",",
                quote(p.timestamp),
                p.application,
                quote(info)
        ) + "\n";

        append(aplicacao, lockApp, line);
    }

    private void writeHeaderIfNeeded(File f, String header) throws IOException {
        if (!f.exists()) {
            try (FileOutputStream fos = new FileOutputStream(f, true)) {
                fos.write(header.getBytes(StandardCharsets.UTF_8));
            }
        }
    }

    private void append(File f, Object lock, String line) {
        synchronized (lock) {
            try (FileOutputStream fos = new FileOutputStream(f, true)) {
                fos.write(line.getBytes(StandardCharsets.UTF_8));
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private String quote(String s) {
        return '"' + s.replace("\"", "'") + '"';
    }
}
