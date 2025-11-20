import java.io.*;

public class RawPacketReader {
    private final Process process;
    private final DataInputStream din;

    public RawPacketReader(String executablePath) throws IOException {
        ProcessBuilder pb = new ProcessBuilder(executablePath);
        pb.redirectErrorStream(true);
        this.process = pb.start();
        this.din = new DataInputStream(new BufferedInputStream(process.getInputStream()));
    }

    public PacketData readPacket() throws IOException {
        int len;
        try {
            len = din.readInt();
        } catch (EOFException e) {
            return null;
        }

        if (len <= 0 || len > 20000) {
            byte[] skip = new byte[Math.max(0, len)];
            din.readFully(skip);
            return null;
        }

        byte[] pkt = new byte[len];
        din.readFully(pkt);
        return new PacketData(pkt);
    }

    public void stop() {
        process.destroy();
    }

    public static class PacketData {
        public final byte[] data;
        public PacketData(byte[] data) { this.data = data; }
    }
}
