package com.lilsniff.model;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;

/**
 * Immutable model representing one captured packet as displayed in the UI.
 */
public class CapturedPacket {

    private static final DateTimeFormatter TIME_FORMATTER =
            DateTimeFormatter.ofPattern("HH:mm:ss.SSS").withZone(ZoneId.systemDefault());

    private final long index;
    private final Instant timestamp;
    private final double relativeTimeSeconds;
    private final double deltaTimeSeconds;
    private final String source;
    private final String destination;
    private final String protocol;
    private final String direction;
    private final String flow;
    private final String appProtocol;
    private final int length;
    private final String info;
    private final String decodeText;
    private final String hexDump;
    private final byte[] rawBytes;

    /**
     * Creates a packet model with decoded metadata, presentation fields, and raw bytes.
     */
    public CapturedPacket(long index,
                          Instant timestamp,
                          double relativeTimeSeconds,
                          double deltaTimeSeconds,
                          String source,
                          String destination,
                          String protocol,
                          String direction,
                          String flow,
                          String appProtocol,
                          int length,
                          String info,
                          String decodeText,
                          String hexDump,
                          byte[] rawBytes) {
        this.index = index;
        this.timestamp = timestamp;
        this.relativeTimeSeconds = relativeTimeSeconds;
        this.deltaTimeSeconds = deltaTimeSeconds;
        this.source = source;
        this.destination = destination;
        this.protocol = protocol;
        this.direction = direction;
        this.flow = flow;
        this.appProtocol = appProtocol;
        this.length = length;
        this.info = info;
        this.decodeText = decodeText;
        this.hexDump = hexDump;
        this.rawBytes = Arrays.copyOf(rawBytes, rawBytes.length);
    }

    public long getIndex() {
        return index;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public String getDisplayTime() {
        return TIME_FORMATTER.format(timestamp);
    }

    public double getRelativeTimeSeconds() {
        return relativeTimeSeconds;
    }

    public double getDeltaTimeSeconds() {
        return deltaTimeSeconds;
    }

    public String getSource() {
        return source;
    }

    public String getDestination() {
        return destination;
    }

    public String getProtocol() {
        return protocol;
    }

    public String getDirection() {
        return direction;
    }

    public String getFlow() {
        return flow;
    }

    public String getAppProtocol() {
        return appProtocol;
    }

    public int getLength() {
        return length;
    }

    public String getInfo() {
        return info;
    }

    public String getDecodeText() {
        return decodeText;
    }

    public String getHexDump() {
        return hexDump;
    }

    public byte[] getRawBytes() {
        return Arrays.copyOf(rawBytes, rawBytes.length);
    }
}
