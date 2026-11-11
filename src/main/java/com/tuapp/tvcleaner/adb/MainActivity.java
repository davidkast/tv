package com.tuapp.tvcleaner.adb;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.net.nsd.NsdManager;
import android.net.nsd.NsdServiceInfo;
import android.os.Bundle;
import android.os.Environment;
import android.os.StatFs;
import android.provider.Settings;
import android.util.Base64;
import android.widget.Toast;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509TrustManager;

public class MainActivity extends Activity {

    private static final int A_CNXN = 0x4e584e43;
    private static final int A_AUTH = 0x48545541;
    private static final int A_STLS = 0x534c5453;
    private static final int A_OPEN = 0x4e45504f;
    private static final int A_OKAY = 0x59414b4f;
    private static final int A_WRTE = 0x45545257;
    private static final int A_CLSE = 0x45534c43;

    private static final int ADB_AUTH_TOKEN = 1;
    private static final int ADB_AUTH_SIGNATURE = 2;
    private static final int ADB_AUTH_RSAPUBLICKEY = 3;
    private static final int A_STLS_VERSION = 0x01000000;

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

                int stoppedApps;
                try {
                    stoppedApps = executeCleanupOverTcp5555(keyPair);
                } catch (Exception tcpEx) {
                    runOnUiThread(() -> Toast.makeText(
                        MainActivity.this,
                        "Puerto 5555 inactivo tras reinicio. Auto-conectando por ADB Wi-Fi...",
                        Toast.LENGTH_SHORT
                    ).show());
                    stoppedApps = executeCleanupOverWirelessTls(keyPair);
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
                        "Aviso ADB: " + e.getMessage(),
                        Toast.LENGTH_LONG
                    ).show();
                    finish();
                });
            }
        }).start();
    }

    private int executeCleanupOverTcp5555(KeyPair keyPair) throws Exception {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("127.0.0.1", 5555), 1800);
            socket.setSoTimeout(25000);

            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();

            connectPlainAdb(in, out, keyPair);
            return runCleanupSequence(in, out, false);
        }
    }

    private int executeCleanupOverWirelessTls(KeyPair keyPair) throws Exception {
        ensureWirelessAdbEnabled(false);

        InetSocketAddress tlsTarget = discoverTlsAdbPort(2800);
        if (tlsTarget == null) {
            ensureWirelessAdbEnabled(true);
            tlsTarget = discoverTlsAdbPort(5000);
        }
        if (tlsTarget == null) {
            throw new Exception("No se detectó puerto ADB Wi-Fi. Concede WRITE_SECURE_SETTINGS o activa Depuración inalámbrica.");
        }

        try (Socket rawSocket = new Socket()) {
            rawSocket.connect(tlsTarget, 4000);
            rawSocket.setSoTimeout(25000);

            InputStream rawIn = rawSocket.getInputStream();
            OutputStream rawOut = rawSocket.getOutputStream();

            sendPacket(rawOut, A_CNXN, 0x01000000, 4096, "host::\0".getBytes(StandardCharsets.UTF_8));
            AdbMessage msg = readPacket(rawIn);

            if (msg.command == A_STLS) {
                sendPacket(rawOut, A_STLS, A_STLS_VERSION, 0, null);

                SSLContext sslContext = createAdbSslContext(keyPair);
                SSLSocket sslSocket = (SSLSocket) sslContext.getSocketFactory().createSocket(
                    rawSocket,
                    tlsTarget.getHostString(),
                    tlsTarget.getPort(),
                    true
                );
                sslSocket.setUseClientMode(true);
                sslSocket.startHandshake();

                InputStream tlsIn = sslSocket.getInputStream();
                OutputStream tlsOut = sslSocket.getOutputStream();

                AdbMessage cnxnMsg = readPacket(tlsIn);
                if (cnxnMsg.command != A_CNXN) {
                    throw new Exception("Clave RSA no autorizada aún en puerto 5555");
                }

                return runCleanupSequence(tlsIn, tlsOut, true);
            } else if (msg.command == A_CNXN) {
                return runCleanupSequence(rawIn, rawOut, true);
            } else {
                throw new Exception("Respuesta inesperada de ADB Wi-Fi");
            }
        }
    }

    private void ensureWirelessAdbEnabled(boolean forceToggle) {
        try {
            Settings.Global.putInt(getContentResolver(), "adb_enabled", 1);
            if (forceToggle) {
                Settings.Global.putInt(getContentResolver(), "adb_wifi_enabled", 0);
                Thread.sleep(400);
            }
            Settings.Global.putInt(getContentResolver(), "adb_wifi_enabled", 1);
            Thread.sleep(500);
        } catch (Exception ignored) {
            // Si aún no tiene WRITE_SECURE_SETTINGS, continúa por si Depuración inalámbrica ya está activa
        }
    }

    private InetSocketAddress discoverTlsAdbPort(long timeoutMs) {
        NsdManager nsdManager = (NsdManager) getSystemService(Context.NSD_SERVICE);
        if (nsdManager == null) return null;

        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<InetSocketAddress> result = new AtomicReference<>(null);

        NsdManager.DiscoveryListener discoveryListener = new NsdManager.DiscoveryListener() {
            @Override
            public void onStartDiscoveryFailed(String serviceType, int errorCode) {
                latch.countDown();
            }

            @Override
            public void onStopDiscoveryFailed(String serviceType, int errorCode) {}

            @Override
            public void onDiscoveryStarted(String serviceType) {}

            @Override
            public void onDiscoveryStopped(String serviceType) {}

            @Override
            public void onServiceFound(NsdServiceInfo serviceInfo) {
                nsdManager.resolveService(serviceInfo, new NsdManager.ResolveListener() {
                    @Override
                    public void onResolveFailed(NsdServiceInfo info, int errorCode) {}

                    @Override
                    public void onServiceResolved(NsdServiceInfo info) {
                        InetAddress host = info.getHost();
                        int port = info.getPort();
                        if (host != null && port > 0) {
                            result.compareAndSet(null, new InetSocketAddress(host, port));
                            latch.countDown();
                        }
                    }
                });
            }

            @Override
            public void onServiceLost(NsdServiceInfo serviceInfo) {}
        };

        try {
            nsdManager.discoverServices("_adb-tls-connect._tcp.", NsdManager.PROTOCOL_DNS_SD, discoveryListener);
            latch.await(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (Exception ignored) {
        } finally {
            try {
                nsdManager.stopServiceDiscovery(discoveryListener);
            } catch (Exception ignored) {}
        }

        return result.get();
    }

    private int runCleanupSequence(InputStream in, OutputStream out, boolean reopenTcp5555) throws Exception {
        int stoppedApps = 0;

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

        if (reopenTcp5555) {
            try {
                byte[] tcpipPayload = "tcpip:5555\0".getBytes(StandardCharsets.UTF_8);
                sendPacket(out, A_OPEN, 5, 0, tcpipPayload);
                readPacket(in);
            } catch (Exception ignored) {
                // Al activar tcpip:5555 el demonio adbd reinicia el socket
            }
        }

        return stoppedApps;
    }

    private void connectPlainAdb(InputStream in, OutputStream out, KeyPair keyPair) throws Exception {
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
        throw new Exception("Acepta el permiso de Depuración USB en la pantalla del TV");
    }

    private SSLContext createAdbSslContext(KeyPair keyPair) throws Exception {
        X509Certificate cert = generateSelfSignedCertificate(keyPair);

        KeyManager km = new X509ExtendedKeyManager() {
            @Override
            public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
                return "adb";
            }

            @Override
            public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
                return null;
            }

            @Override
            public X509Certificate[] getCertificateChain(String alias) {
                return new X509Certificate[]{cert};
            }

            @Override
            public String[] getClientAliases(String keyType, Principal[] issuers) {
                return new String[]{"adb"};
            }

            @Override
            public PrivateKey getPrivateKey(String alias) {
                return keyPair.getPrivate();
            }

            @Override
            public String[] getServerAliases(String keyType, Principal[] issuers) {
                return null;
            }
        };

        TrustManager tm = new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) {}

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) {}

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        };

        SSLContext sc = SSLContext.getInstance("TLSv1.3");
        sc.init(new KeyManager[]{km}, new TrustManager[]{tm}, new SecureRandom());
        return sc;
    }

    private X509Certificate generateSelfSignedCertificate(KeyPair kp) throws Exception {
        byte[] pubKeyEncoded = kp.getPublic().getEncoded();

        byte[] cnOid = new byte[]{0x06, 0x03, 0x55, 0x04, 0x03};
        byte[] cnVal = derTag(0x0C, "adb".getBytes(StandardCharsets.UTF_8));
        byte[] atv = derTag(0x30, concat(cnOid, cnVal));
        byte[] rdn = derTag(0x31, atv);
        byte[] name = derTag(0x30, rdn);

        byte[] notBefore = derTag(0x17, "240101000000Z".getBytes(StandardCharsets.US_ASCII));
        byte[] notAfter  = derTag(0x17, "491231235959Z".getBytes(StandardCharsets.US_ASCII));
        byte[] validity  = derTag(0x30, concat(notBefore, notAfter));

        byte[] version = derTag(0xA0, new byte[]{0x02, 0x01, 0x02});
        byte[] serial = new byte[]{0x02, 0x01, 0x01};
        byte[] sigAlg = new byte[]{
            0x30, 0x0D,
            0x06, 0x09, 0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x01, 0x0B,
            0x05, 0x00
        };

        byte[] tbsCert = derTag(0x30, concat(
            version,
            serial,
            sigAlg,
            name,
            validity,
            name,
            pubKeyEncoded
        ));

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(kp.getPrivate());
        sig.update(tbsCert);
        byte[] signatureBytes = sig.sign();

        byte[] bitStringPayload = new byte[signatureBytes.length + 1];
        bitStringPayload[0] = 0x00;
        System.arraycopy(signatureBytes, 0, bitStringPayload, 1, signatureBytes.length);
        byte[] sigBitString = derTag(0x03, bitStringPayload);

        byte[] certDer = derTag(0x30, concat(tbsCert, sigAlg, sigBitString));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certDer));
    }

    private byte[] derTag(int tag, byte[] content) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        int len = content.length;
        if (len < 128) {
            out.write(len);
        } else if (len < 256) {
            out.write(0x81);
            out.write(len);
        } else {
            out.write(0x82);
            out.write((len >> 8) & 0xFF);
            out.write(len & 0xFF);
        }
        out.write(content, 0, len);
        return out.toByteArray();
    }

    private byte[] concat(byte[]... arrays) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] a : arrays) {
            out.write(a, 0, a.length);
        }
        return out.toByteArray();
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
