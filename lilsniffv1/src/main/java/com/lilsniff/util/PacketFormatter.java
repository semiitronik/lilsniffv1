package com.lilsniff.util;

import com.lilsniff.model.CapturedPacket;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.Set;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV6CommonPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

public final class PacketFormatter {

    private PacketFormatter() {
    }

    public static PacketSummary summarize(Packet packet, Set<String> localAddresses) {
        EndpointPair endpointPair = resolveEndpoints(packet);
        Integer srcPort = null;
        Integer dstPort = null;
        String protocol = packet.getClass().getSimpleName();
        String appProtocol = "-";
        String info = packet.toString().replaceAll("\\s+", " ");

        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        if (tcpPacket != null) {
            srcPort = tcpPacket.getHeader().getSrcPort().valueAsInt();
            dstPort = tcpPacket.getHeader().getDstPort().valueAsInt();
            protocol = "TCP";
            appProtocol = identifyApplicationProtocol(srcPort, dstPort);
            info = "TCP " + formatTcpFlags(tcpPacket)
                    + " " + srcPort + " -> " + dstPort
                    + maybeAppSuffix(appProtocol);
        } else {
            UdpPacket udpPacket = packet.get(UdpPacket.class);
            if (udpPacket != null) {
                srcPort = udpPacket.getHeader().getSrcPort().valueAsInt();
                dstPort = udpPacket.getHeader().getDstPort().valueAsInt();
                appProtocol = identifyApplicationProtocol(srcPort, dstPort);
                protocol = "UDP";
                info = "UDP " + srcPort + " -> " + dstPort + maybeAppSuffix(appProtocol);
            } else {
                ArpPacket arpPacket = packet.get(ArpPacket.class);
                if (arpPacket != null) {
                    protocol = "ARP";
                    info = "ARP " + arpPacket.getHeader().getOperation()
                            + " " + arpPacket.getHeader().getSrcProtocolAddr().getHostAddress()
                            + " -> " + arpPacket.getHeader().getDstProtocolAddr().getHostAddress();
                } else {
                    IcmpV6CommonPacket icmpV6Packet = packet.get(IcmpV6CommonPacket.class);
                    if (icmpV6Packet != null) {
                        protocol = "ICMPv6";
                        int type = toUnsignedByte(icmpV6Packet.getHeader().getType().value());
                        int code = toUnsignedByte(icmpV6Packet.getHeader().getCode().value());
                        info = "ICMPv6 " + icmpV6TypeName(type) + " (type=" + type + ", code=" + code + ")";
                    } else {
                        IcmpV4CommonPacket icmpV4Packet = packet.get(IcmpV4CommonPacket.class);
                        if (icmpV4Packet != null) {
                            protocol = "ICMP";
                            int type = toUnsignedByte(icmpV4Packet.getHeader().getType().value());
                            int code = toUnsignedByte(icmpV4Packet.getHeader().getCode().value());
                            info = "ICMP type=" + type + ", code=" + code;
                        } else {
                            IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
                            if (ipV4Packet != null) {
                                protocol = "IPv4";
                                info = "IPv4 " + ipV4Packet.getHeader().getProtocol();
                            } else {
                                IpV6Packet ipV6Packet = packet.get(IpV6Packet.class);
                                if (ipV6Packet != null) {
                                    protocol = "IPv6";
                                    info = "IPv6 " + ipV6Packet.getHeader().getNextHeader();
                                }
                            }
                        }
                    }
                }
            }
        }

        String protocolLabel = "-".equals(appProtocol) ? protocol : protocol + "/" + appProtocol;
        String direction = classifyDirection(endpointPair.source(), endpointPair.destination(), localAddresses);
        String flowKey = buildFlowKey(protocol, endpointPair, srcPort, dstPort);
        String flowLabel = buildFlowLabel(protocol, endpointPair, srcPort, dstPort);

        return new PacketSummary(
                endpointPair.source(),
                endpointPair.destination(),
                protocolLabel,
                appProtocol,
                info,
                direction,
                flowKey,
                flowLabel,
                packet.getRawData().length,
                packet.toString());
    }

    public static CapturedPacket toCapturedPacket(long index,
                                                  Instant timestamp,
                                                  double relativeTimeSeconds,
                                                  double deltaTimeSeconds,
                                                  Packet packet,
                                                  PacketSummary summary,
                                                  long flowPacketCount,
                                                  long flowBytes) {
        byte[] rawData = packet.getRawData();
        String decodeText = buildDecodeText(timestamp, relativeTimeSeconds, deltaTimeSeconds, summary,
                flowPacketCount, flowBytes, packet);

        return new CapturedPacket(
                index,
                timestamp,
                relativeTimeSeconds,
                deltaTimeSeconds,
                summary.source(),
                summary.destination(),
                summary.protocolLabel(),
                summary.direction(),
                summary.flowLabel(),
                summary.appProtocol(),
                summary.length(),
                summary.info(),
                decodeText,
                toHexDump(rawData),
                rawData);
    }

    private static EndpointPair resolveEndpoints(Packet packet) {
        IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
        if (ipV4Packet != null) {
            return new EndpointPair(
                    ipV4Packet.getHeader().getSrcAddr().getHostAddress(),
                    ipV4Packet.getHeader().getDstAddr().getHostAddress());
        }

        IpV6Packet ipV6Packet = packet.get(IpV6Packet.class);
        if (ipV6Packet != null) {
            return new EndpointPair(
                    ipV6Packet.getHeader().getSrcAddr().getHostAddress(),
                    ipV6Packet.getHeader().getDstAddr().getHostAddress());
        }

        ArpPacket arpPacket = packet.get(ArpPacket.class);
        if (arpPacket != null) {
            return new EndpointPair(
                    arpPacket.getHeader().getSrcProtocolAddr().getHostAddress(),
                    arpPacket.getHeader().getDstProtocolAddr().getHostAddress());
        }

        EthernetPacket ethernetPacket = packet.get(EthernetPacket.class);
        if (ethernetPacket != null) {
            return new EndpointPair(
                    ethernetPacket.getHeader().getSrcAddr().toString(),
                    ethernetPacket.getHeader().getDstAddr().toString());
        }

        return new EndpointPair("-", "-");
    }

    private static String classifyDirection(String source, String destination, Set<String> localAddresses) {
        boolean sourceLocal = localAddresses.contains(source);
        boolean destinationLocal = localAddresses.contains(destination);
        if (sourceLocal && !destinationLocal) {
            return "OUTBOUND";
        }
        if (!sourceLocal && destinationLocal) {
            return "INBOUND";
        }
        if (sourceLocal) {
            return "LOCAL";
        }
        return "UNKNOWN";
    }

    private static String buildFlowKey(String protocol, EndpointPair pair, Integer srcPort, Integer dstPort) {
        String endpointA = pair.source() + ":" + portText(srcPort);
        String endpointB = pair.destination() + ":" + portText(dstPort);
        if (endpointA.compareTo(endpointB) <= 0) {
            return protocol + "|" + endpointA + "|" + endpointB;
        }
        return protocol + "|" + endpointB + "|" + endpointA;
    }

    private static String buildFlowLabel(String protocol, EndpointPair pair, Integer srcPort, Integer dstPort) {
        return pair.source() + ":" + portText(srcPort)
                + " <-> "
                + pair.destination() + ":" + portText(dstPort)
                + " (" + protocol + ")";
    }

    private static String portText(Integer port) {
        return port == null ? "-" : String.valueOf(port);
    }

    private static String formatTcpFlags(TcpPacket tcpPacket) {
        StringBuilder flags = new StringBuilder("[");
        appendFlag(flags, tcpPacket.getHeader().getSyn(), "SYN");
        appendFlag(flags, tcpPacket.getHeader().getAck(), "ACK");
        appendFlag(flags, tcpPacket.getHeader().getPsh(), "PSH");
        appendFlag(flags, tcpPacket.getHeader().getFin(), "FIN");
        appendFlag(flags, tcpPacket.getHeader().getRst(), "RST");
        appendFlag(flags, tcpPacket.getHeader().getUrg(), "URG");
        if (flags.length() == 1) {
            flags.append("NONE");
        }
        flags.append(']');
        return flags.toString();
    }

    private static void appendFlag(StringBuilder flags, boolean enabled, String label) {
        if (!enabled) {
            return;
        }
        if (flags.length() > 1) {
            flags.append(", ");
        }
        flags.append(label);
    }

    private static String identifyApplicationProtocol(Integer srcPort, Integer dstPort) {
        int[] ports = {srcPort == null ? -1 : srcPort, dstPort == null ? -1 : dstPort};
        for (int port : ports) {
            switch (port) {
                case 53:
                    return "DNS";
                case 67:
                case 68:
                    return "DHCP";
                case 80:
                    return "HTTP";
                case 123:
                    return "NTP";
                case 161:
                    return "SNMP";
                case 443:
                    return "HTTPS";
                case 22:
                    return "SSH";
                case 25:
                    return "SMTP";
                case 110:
                    return "POP3";
                case 143:
                    return "IMAP";
                case 1900:
                    return "SSDP";
                case 27036:
                    return "STEAM";
                default:
                    break;
            }
        }
        return "-";
    }

    private static String maybeAppSuffix(String appProtocol) {
        return "-".equals(appProtocol) ? "" : " (" + appProtocol + ")";
    }

    private static int toUnsignedByte(byte value) {
        return value & 0xFF;
    }

    private static String icmpV6TypeName(int type) {
        return switch (type) {
            case 128 -> "Echo Request";
            case 129 -> "Echo Reply";
            case 133 -> "Router Solicitation";
            case 134 -> "Router Advertisement";
            case 135 -> "Neighbor Solicitation";
            case 136 -> "Neighbor Advertisement";
            case 137 -> "Redirect";
            default -> "Type " + type;
        };
    }

    private static String buildDecodeText(Instant timestamp,
                                          double relativeTimeSeconds,
                                          double deltaTimeSeconds,
                                          PacketSummary summary,
                                          long flowPacketCount,
                                          long flowBytes,
                                          Packet packet) {
        return "Timestamp: " + timestamp + System.lineSeparator()
                + String.format("Relative Time: %.6f s%n", relativeTimeSeconds)
                + String.format("Delta Time: %.6f s%n", deltaTimeSeconds)
                + "Source: " + summary.source() + System.lineSeparator()
                + "Destination: " + summary.destination() + System.lineSeparator()
                + "Direction: " + summary.direction() + System.lineSeparator()
                + "Protocol: " + summary.protocolLabel() + System.lineSeparator()
                + "Application Hint: " + summary.appProtocol() + System.lineSeparator()
                + "Length: " + summary.length() + " bytes" + System.lineSeparator()
                + "Info: " + summary.info() + System.lineSeparator()
                + System.lineSeparator()
                + "Flow: " + summary.flowLabel() + System.lineSeparator()
                + "Flow Packets: " + flowPacketCount + System.lineSeparator()
                + "Flow Bytes: " + flowBytes + System.lineSeparator()
                + System.lineSeparator()
                + "Decoded Packet:" + System.lineSeparator()
                + packet;
    }

    public static String toHexDump(byte[] bytes) {
        if (bytes.length == 0) {
            return "<empty>";
        }

        StringBuilder builder = new StringBuilder();
        for (int offset = 0; offset < bytes.length; offset += 16) {
            int lineLength = Math.min(16, bytes.length - offset);
            builder.append(String.format("%04X  ", offset));

            for (int i = 0; i < 16; i++) {
                if (i < lineLength) {
                    builder.append(String.format("%02X ", bytes[offset + i] & 0xFF));
                } else {
                    builder.append("   ");
                }
            }

            builder.append(" |");
            builder.append(toSafeAscii(Arrays.copyOfRange(bytes, offset, offset + lineLength)));
            builder.append('|').append(System.lineSeparator());
        }
        return builder.toString();
    }

    public static String toSafeAscii(byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length);
        String text = new String(bytes, StandardCharsets.UTF_8);
        for (char character : text.toCharArray()) {
            builder.append(character >= 32 && character <= 126 ? character : '.');
        }
        return builder.toString();
    }

    public record PacketSummary(String source,
                                String destination,
                                String protocolLabel,
                                String appProtocol,
                                String info,
                                String direction,
                                String flowKey,
                                String flowLabel,
                                int length,
                                String decodedPacket) {
    }

    private record EndpointPair(String source, String destination) {
    }
}
