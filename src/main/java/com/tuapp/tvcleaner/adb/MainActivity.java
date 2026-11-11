package com.tuapp.tvcleaner.adb;

import android.app.Activity;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.Environment;
import android.os.StatFs;
import android.util.Base64;
import android.widget.Toast;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class MainActivity extends Activity {

    private static final int A_CNXN = 0x4e584e43;
    private static final int A_AUTH = 0x48545541;
    private static final int A_OPEN = 0x4e45504f;
    private static final int A_OKAY = 0x59414b4f;
    private static final int A_WRTE = 0x45545257;
    private static final int A_CLSE = 0x45534c43;

    private static final int ADB_AUTH_TOKEN = 1;
    private static final int ADB_AUTH_SIGNATURE = 2;
    private static final int ADB_AUTH_RSAPUBLICKEY = 3;

    private static final byte[] SHA1_DIGEST_INFO = new byte[]{
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
        0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Toast.makeText(this, "Cerrando apps y limpiando caché...", Toast.LENGTH_SHORT).show();

        new Thread(() -> {
            try {
                long freeBefore = getAvailableMegabytes();
                KeyPair keyPair = getOrCreateKeyPair();

                int stoppedApps = 0;

                try (Socket socket = new Socket()) {
                    socket.connect(new InetSocketAddress("127.0.0.1", 5555), 5000);
                    socket.setSoTimeout(30000);

                    InputStream in = socket.getInputStream();
                    OutputStream out = socket.getOutputStream();

                    connectAdb(in, out, keyPair);

                    runShellCommand(in, out, 1, "pm trim-caches 999G");

                    String runningOutput = runShellCommand(in, out, 2, "ps -A");
                    String packagesOutput = runShellCommand(in, out, 3, "pm list packages -3");

                    Set<String> whitelist = new HashSet<>(Arrays.asList(
                        "com.tuapp.tvcleaner",
                        "com.tuapp.tvcleaner.adb",
                        "me.efesser.flauncher",
                        "com.spocky.projengmenu",
                        "com.wolf.firelauncher",
                        "flar2.homebutton",
                        "dev.vodik7.tvquickactions"
                    ));

                    List<String> targetPackages = new ArrayList<>(Arrays.asList(
                        "com.google.android.youtube.tv",
                        "com.google.android.youtube.tvmusic",
                        "com.netflix.ninja",
                        "com.amazon.amazonvideo.livingroom"
                    ));

                    for (String line : packagesOutput.split("\r?\n")) {
                        String pkg = line.replace("package:", "").trim();
                        if (!pkg.isEmpty() && !targetPackages.contains(pkg)) {
                            targetPackages.add(pkg);
                        }
                    }

                    StringBuilder stopCmd = new StringBuilder();
                    for (String pkg : targetPackages) {
                        if (whitelist.contains(pkg)) continue;
                        if (runningOutput.contains(pkg)) {
                            stoppedApps++;
                        }
                        if (stopCmd.length() > 0) stopCmd.append("; ");
                        stopCmd.append("am force-stop ").append(pkg);
                    }

                    if (stopCmd.length() > 0) {
                        runShellCommand(in, out, 4, stopCmd.toString());
                    }
                }

                long freeAfter = getAvailableMegabytes();
                long freed = Math.max(0, freeAfter - freeBefore);
                final int finalStopped = stoppedApps;

                runOnUiThread(() -> {
                    Toast.makeText(
                        MainActivity.this,
                        "Apps cerradas: " + finalStopped + " | Caché liberada: " + freed + " MB (Libre: " + freeAfter + " MB)",
                        Toast.LENGTH_LONG
                    ).show();
                    finish();
                });

            } catch (Exception e) {
                runOnUiThread(() -> {
                    Toast.makeText(
                        MainActivity.this,
                        "Activa Depuración ADB (puerto 5555) y acepta el permiso en pantalla: " + e.getMessage(),
                        Toast.LENGTH_LONG
                    ).show();
                    finish();
                });
            }
        }).start();
    }

    private void connectAdb(InputStream in, OutputStream out, KeyPair keyPair) throws Exception {
        sendPacket(out, A_CNXN, 0x01000000, 4096, "host::\0".getBytes(StandardCharsets.UTF_8));

        AdbMessage msg = readPacket(in);
        if (msg.command == A_CNXN) {
            return;
        }

        if (msg.command == A_AUTH && msg.arg0 == ADB_AUTH_TOKEN) {
            byte[] signature = signToken(keyPair.getPrivate(), msg.payload);
            sendPacket(out, A_AUTH, ADB_AUTH_SIGNATURE, 0, signature);

            msg = readPacket(in);
            if (msg.command == A_CNXN) {
                return;
            }

            if (msg.command == A_AUTH && msg.arg0 == ADB_AUTH_TOKEN) {
                byte[] pubKeyPayload = encodeAdbPublicKey((RSAPublicKey) keyPair.getPublic());
                sendPacket(out, A_AUTH, ADB_AUTH_RSAPUBLICKEY, 0, pubKeyPayload);

                msg = readPacket(in);
                if (msg.command == A_CNXN) {
                    return;
                }
            }
        }
        throw new Exception("Autorización ADB pendiente o rechazada");
    }

    private String runShellCommand(InputStream in, OutputStream out, int localId, String cmd) throws Exception {
        byte[] openPayload = ("shell:" + cmd + "\0").getBytes(StandardCharsets.UTF_8);
        sendPacket(out, A_OPEN, localId, 0, openPayload);

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        int remoteId = 0;

        while (true) {
            AdbMessage msg = readPacket(in);
            if (msg.command == A_OKAY) {
                remoteId = msg.arg0;
            } else if (msg.command == A_WRTE) {
                remoteId = msg.arg0;
                if (msg.payload != null && msg.payload.length > 0) {
                    output.write(msg.payload);
                }
                sendPacket(out, A_OKAY, localId, remoteId, null);
            } else if (msg.command == A_CLSE) {
                sendPacket(out, A_CLSE, localId, remoteId, null);
                break;
            }
        }
        return new String(output.toByteArray(), StandardCharsets.UTF_8);
    }

    private static class AdbMessage {
        int command;
        int arg0;
        int arg1;
        byte[] payload;
    }

    private void sendPacket(OutputStream out, int command, int arg0, int arg1, byte[] payload) throws Exception {
        int len = (payload == null) ? 0 : payload.length;
        int checksum = 0;
        if (payload != null) {
            for (byte b : payload) {
                checksum += (b & 0xFF);
            }
        }
        ByteBuffer buf = ByteBuffer.allocate(24 + len).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt(command);
        buf.putInt(arg0);
        buf.putInt(arg1);
        buf.putInt(len);
        buf.putInt(checksum);
        buf.putInt(command ^ 0xFFFFFFFF);
        if (payload != null) {
            buf.put(payload);
        }
        out.write(buf.array());
        out.flush();
    }

    private AdbMessage readPacket(InputStream in) throws Exception {
        byte[] header = readFully(in, 24);
        ByteBuffer buf = ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN);
        AdbMessage msg = new AdbMessage();
        msg.command = buf.getInt();
        msg.arg0 = buf.getInt();
        msg.arg1 = buf.getInt();
        int len = buf.getInt();
        buf.getInt(); // checksum
        buf.getInt(); // magic
        if (len > 0) {
            msg.payload = readFully(in, len);
        } else {
            msg.payload = new byte[0];
        }
        return msg;
    }

    private byte[] readFully(InputStream in, int len) throws Exception {
        byte[] data = new byte[len];
        int offset = 0;
        while (offset < len) {
            int read = in.read(data, offset, len - offset);
            if (read < 0) throw new Exception("Conexión ADB cerrada");
            offset += read;
        }
        return data;
    }

    private byte[] signToken(PrivateKey privateKey, byte[] token) throws Exception {
        byte[] data = new byte[SHA1_DIGEST_INFO.length + token.length];
        System.arraycopy(SHA1_DIGEST_INFO, 0, data, 0, SHA1_DIGEST_INFO.length);
        System.arraycopy(token, 0, data, SHA1_DIGEST_INFO.length, token.length);
        Signature sig = Signature.getInstance("NONEwithRSA");
        sig.initSign(privateKey);
        sig.update(data);
        return sig.sign();
    }

    private byte[] encodeAdbPublicKey(RSAPublicKey pubKey) {
        BigInteger n = pubKey.getModulus();
        BigInteger r32 = BigInteger.ONE.shiftLeft(32);
        BigInteger n0inv = r32.subtract(n.modInverse(r32));
        BigInteger rr = BigInteger.ONE.shiftLeft(4096).mod(n);

        ByteBuffer buf = ByteBuffer.allocate(524).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt(64);
        buf.putInt((int) n0inv.longValue());
        buf.put(toLittleEndian256(n));
        buf.put(toLittleEndian256(rr));
        buf.putInt(pubKey.getPublicExponent().intValue());

        String b64 = Base64.encodeToString(buf.array(), Base64.NO_WRAP);
        return (b64 + " tvcleaner@tv\0").getBytes(StandardCharsets.UTF_8);
    }

    private byte[] toLittleEndian256(BigInteger val) {
        byte[] be = val.toByteArray();
        byte[] le = new byte[256];
        int srcIdx = be.length - 1;
        for (int i = 0; i < 256 && srcIdx >= 0; i++, srcIdx--) {
            le[i] = be[srcIdx];
        }
        return le;
    }

    private KeyPair getOrCreateKeyPair() throws Exception {
        SharedPreferences prefs = getSharedPreferences("adb_keys", MODE_PRIVATE);
        String privB64 = prefs.getString("priv", null);
        String pubB64 = prefs.getString("pub", null);

        if (privB64 != null && pubB64 != null) {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(Base64.decode(privB64, Base64.DEFAULT)));
            RSAPublicKey pub = (RSAPublicKey) kf.generatePublic(new X509EncodedKeySpec(Base64.decode(pubB64, Base64.DEFAULT)));
            return new KeyPair(pub, priv);
        }

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        prefs.edit()
            .putString("priv", Base64.encodeToString(kp.getPrivate().getEncoded(), Base64.NO_WRAP))
            .putString("pub", Base64.encodeToString(kp.getPublic().getEncoded(), Base64.NO_WRAP))
            .apply();

        return kp;
    }

    private long getAvailableMegabytes() {
        StatFs stat = new StatFs(Environment.getDataDirectory().getPath());
        return stat.getAvailableBytes() / (1024 * 1024);
    }
}
