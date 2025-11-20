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

        writeHeaderIfNeeded(internet, "timestamp,protocolo,ip_origem,ip_destino,proto_num,tamanho_bytes\n");
        writeHeaderIfNeeded(transporte, "timestamp,protocolo,ip_origem,porta_origem,ip_destino,porta_destino,tamanho_bytes\n");
        writeHeaderIfNeeded(aplicacao, "timestamp,protocolo,info\n");
    }

    private void writeHeaderIfNeeded(File f, String header) throws IOException {
        if (!f.exists()) {
            try (FileOutputStream fos = new FileOutputStream(f, true)) {
                fos.write(header.getBytes(StandardCharsets.UTF_8));
            }
        }
    }

    public void logInternet(PacketParser.ParsedPacket p) {
        String line = String.join(",",
                quote(p.timestamp), p.protocol, p.src, p.dst, "-", String.valueOf(p.totalBytes)) + "\n";
        append(internet, lockInet, line);
    }

    public void logTransporte(PacketParser.ParsedPacket p) {
        String line = String.join(",",
                quote(p.timestamp), p.transport, p.src,
                p.sport<0?"-":String.valueOf(p.sport),
                p.dst,
                p.dport<0?"-":String.valueOf(p.dport),
                String.valueOf(p.totalBytes)) + "\n";
        append(transporte, lockTransp, line);
    }

    public void logAplicacao(String ts, String proto, String info) {
        String line = String.join(",", quote(ts), proto, quote(info)) + "\n";
        append(aplicacao, lockApp, line);
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
