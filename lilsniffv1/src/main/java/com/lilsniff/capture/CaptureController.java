package com.lilsniff.capture;

import com.lilsniff.model.CapturedPacket;
import com.lilsniff.util.PacketFormatter;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicLong;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;

/**
 * Manages live capture lifecycle and packet transformation for the UI.
 * Handles interface discovery, capture start/stop, timing metrics, and basic flow stats.
 */
public class CaptureController {

    private static final int SNAPLEN = 65536;
    private static final int READ_TIMEOUT_MILLIS = 50;

    private final ExecutorService executorService = Executors.newSingleThreadExecutor();
    private final AtomicLong packetCounter = new AtomicLong(0L);

    private volatile boolean capturing;
    private volatile PcapHandle handle;
    private volatile Future<?> captureTask;
    private volatile Instant firstPacketTimestamp;
    private volatile Instant previousPacketTimestamp;
    private volatile Set<String> localAddresses = Set.of();
    private final Map<String, FlowStats> flowStats = new HashMap<>();

    /**
     * Returns available network interfaces visible to Pcap4J.
     */
    public List<PcapNetworkInterface> listInterfaces() {
        try {
            List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();
            return interfaces == null ? List.of() : new ArrayList<>(interfaces);
        } catch (PcapNativeException exception) {
            throw new IllegalStateException("Unable to list network interfaces.", exception);
        }
    }

    public synchronized boolean isCapturing() {
        return capturing;
    }

    /**
     * Starts live capture on the selected interface and begins background packet polling.
     */
    public synchronized void startCapture(PcapNetworkInterface networkInterface, CaptureListener listener) {
        if (capturing) {
            return;
        }

        try {
            packetCounter.set(0L);
            firstPacketTimestamp = null;
            previousPacketTimestamp = null;
            flowStats.clear();
            localAddresses = resolveLocalAddresses(networkInterface);
            handle = networkInterface.openLive(
                    SNAPLEN,
                    PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
                    READ_TIMEOUT_MILLIS);
            capturing = true;
            listener.onCaptureStarted(networkInterface.getName());

            captureTask = executorService.submit(() -> runCaptureLoop(listener));
        } catch (PcapNativeException exception) {
            throw new IllegalStateException("Unable to start live capture.", exception);
        }
    }

    /**
     * Stops capture and closes any active handle.
     */
    public synchronized void stopCapture() {
        capturing = false;
        closeHandle();
        if (captureTask != null) {
            captureTask.cancel(true);
            captureTask = null;
        }
    }

    /**
     * Stops capture and shuts down controller resources.
     */
    public synchronized void shutdown() {
        stopCapture();
        executorService.shutdownNow();
    }

    /**
     * Continuously reads packets while capture is active and publishes them through the listener.
     */
    private void runCaptureLoop(CaptureListener listener) {
        while (capturing && handle != null && handle.isOpen()) {
            try {
                Packet packet = handle.getNextPacket();
                if (packet == null) {
                    continue;
                }

                long index = packetCounter.incrementAndGet();
                Instant timestamp = resolveTimestamp();
                double relativeTimeSeconds = toSeconds(firstPacketTimestamp == null
                        ? Duration.ZERO
                        : Duration.between(firstPacketTimestamp, timestamp));
                double deltaTimeSeconds = toSeconds(previousPacketTimestamp == null
                        ? Duration.ZERO
                        : Duration.between(previousPacketTimestamp, timestamp));
                if (firstPacketTimestamp == null) {
                    firstPacketTimestamp = timestamp;
                    relativeTimeSeconds = 0.0;
                }
                previousPacketTimestamp = timestamp;

                PacketFormatter.PacketSummary summary = PacketFormatter.summarize(packet, localAddresses);
                FlowStats stats = flowStats.computeIfAbsent(summary.flowKey(), ignored -> new FlowStats());
                stats.packets++;
                stats.bytes += summary.length();

                CapturedPacket capturedPacket = PacketFormatter.toCapturedPacket(
                        index,
                        timestamp,
                        relativeTimeSeconds,
                        deltaTimeSeconds,
                        packet,
                        summary,
                        stats.packets,
                        stats.bytes);
                listener.onPacketCaptured(capturedPacket);
            } catch (NotOpenException | RuntimeException exception) {
                if (capturing) {
                    listener.onCaptureError("Unable to read packets from the selected interface.", exception);
                }
                break;
            }
        }

        closeHandle();
        capturing = false;
        listener.onCaptureStopped();
    }

    private Instant resolveTimestamp() throws NotOpenException {
        if (handle == null) {
            return Instant.now();
        }
        Timestamp timestamp = handle.getTimestamp();
        return timestamp == null ? Instant.now() : timestamp.toInstant();
    }

    private synchronized void closeHandle() {
        if (handle != null && handle.isOpen()) {
            handle.close();
        }
        handle = null;
    }

    private Set<String> resolveLocalAddresses(PcapNetworkInterface networkInterface) {
        Set<String> addresses = new HashSet<>();
        for (PcapAddress address : networkInterface.getAddresses()) {
            if (address.getAddress() != null) {
                addresses.add(address.getAddress().getHostAddress());
            }
        }
        return addresses;
    }

    private double toSeconds(Duration duration) {
        return duration.toNanos() / 1_000_000_000.0;
    }

    private static final class FlowStats {
        private long packets;
        private long bytes;
    }
}
