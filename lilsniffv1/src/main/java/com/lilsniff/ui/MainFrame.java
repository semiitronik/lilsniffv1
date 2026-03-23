package com.lilsniff.ui;

import com.lilsniff.capture.CaptureController;
import com.lilsniff.capture.CaptureListener;
import com.lilsniff.model.CapturedPacket;
import com.lilsniff.util.PacketFormatter;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Image;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.DefaultComboBoxModel;
import javax.swing.DefaultListCellRenderer;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.WindowConstants;
import javax.swing.event.ListSelectionListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.ImageIcon;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import org.pcap4j.core.PcapNetworkInterface;

/**
 * Main LilSniff Swing window.
 * Provides interface selection, live capture controls, packet list, detail panes, and note export.
 */
public class MainFrame extends JFrame implements CaptureListener {

    private static final String[] COLUMN_NAMES = {
            "No.", "Time", "Rel(s)", "Delta(s)", "Direction", "Source", "Destination", "Protocol", "Length", "Flow", "Info"
    };
    private static final DecimalFormat TIME_FORMAT = new DecimalFormat("0.000000");

    private static final Color BG_BASE = new Color(255, 241, 246);
    private static final Color BG_PANEL = new Color(255, 228, 238);
    private static final Color BG_TABLE_ALT = new Color(255, 235, 243);
    private static final Color BG_SELECTION = new Color(244, 168, 203);
    private static final Color BORDER_COLOR = new Color(226, 159, 187);
    private static final Color TEXT_COLOR = new Color(72, 30, 49);

    private final CaptureController captureController;
    private final List<CapturedPacket> packets = new ArrayList<>();

    private final DefaultComboBoxModel<PcapNetworkInterface> interfaceModel = new DefaultComboBoxModel<>();
    private final JComboBox<PcapNetworkInterface> interfaceComboBox = new JComboBox<>(interfaceModel);
    private final JButton refreshButton = new JButton("Refresh");
    private final JButton startButton = new JButton("Start");
    private final JButton stopButton = new JButton("Stop");
    private final JButton clearButton = new JButton("Clear");
    private final JButton exportNoteButton = new JButton("Export Note");
    private final JLabel logoLabel = new JLabel();
    private final JLabel statusLabel = new JLabel("Ready");

    private final DefaultTableModel tableModel = new DefaultTableModel(COLUMN_NAMES, 0) {
        @Override
        public boolean isCellEditable(int row, int column) {
            return false;
        }
    };
    private final JTable packetTable = new JTable(tableModel);

    private final JTextArea decodeArea = createReadOnlyTextArea();
    private final JTextArea hexArea = createReadOnlyTextArea();
    private final JTextArea asciiArea = createReadOnlyTextArea();

    /**
     * Builds the main window and loads available interfaces on startup.
     */
    public MainFrame(CaptureController captureController) {
        super("LilSniff");
        this.captureController = captureController;
        configureFrame();
        buildLayout();
        wireEvents();
        refreshInterfaces();
    }

    private void configureFrame() {
        setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        setMinimumSize(new Dimension(1200, 760));
        setSize(new Dimension(1480, 860));
        setLocationRelativeTo(null);
        addWindowListener(new java.awt.event.WindowAdapter() {
            @Override
            public void windowClosing(java.awt.event.WindowEvent event) {
                captureController.shutdown();
            }
        });
    }

    private void buildLayout() {
        JPanel topBar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        topBar.setBorder(BorderFactory.createEmptyBorder(8, 8, 4, 8));
        interfaceComboBox.setPreferredSize(new Dimension(430, 28));
        interfaceComboBox.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list,
                                                          Object value,
                                                          int index,
                                                          boolean isSelected,
                                                          boolean cellHasFocus) {
                Component component =
                        super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                if (value instanceof PcapNetworkInterface networkInterface) {
                    String description = networkInterface.getDescription();
                    setText((description == null || description.isBlank())
                            ? networkInterface.getName()
                            : networkInterface.getName() + " - " + description);
                }
                return component;
            }
        });
        stopButton.setEnabled(false);
        setupLogoLabel();

        topBar.add(logoLabel);
        topBar.add(new JLabel("Interface:"));
        topBar.add(interfaceComboBox);
        topBar.add(refreshButton);
        topBar.add(startButton);
        topBar.add(stopButton);
        topBar.add(clearButton);
        topBar.add(exportNoteButton);

        packetTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        packetTable.setAutoCreateRowSorter(true);
        packetTable.setFillsViewportHeight(true);
        packetTable.getColumnModel().getColumn(0).setPreferredWidth(65);
        packetTable.getColumnModel().getColumn(1).setPreferredWidth(105);
        packetTable.getColumnModel().getColumn(2).setPreferredWidth(85);
        packetTable.getColumnModel().getColumn(3).setPreferredWidth(85);
        packetTable.getColumnModel().getColumn(4).setPreferredWidth(95);
        packetTable.getColumnModel().getColumn(5).setPreferredWidth(180);
        packetTable.getColumnModel().getColumn(6).setPreferredWidth(180);
        packetTable.getColumnModel().getColumn(7).setPreferredWidth(100);
        packetTable.getColumnModel().getColumn(8).setPreferredWidth(75);
        packetTable.getColumnModel().getColumn(9).setPreferredWidth(300);
        packetTable.getColumnModel().getColumn(10).setPreferredWidth(430);
        packetTable.setDefaultRenderer(Object.class, new PacketTableRenderer());

        JScrollPane packetScrollPane = new JScrollPane(packetTable);
        packetScrollPane.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(BORDER_COLOR), "Packet List"));

        JTabbedPane detailsTabs = new JTabbedPane();
        detailsTabs.addTab("Packet Details", new JScrollPane(decodeArea));
        detailsTabs.addTab("Hex View", new JScrollPane(hexArea));
        detailsTabs.addTab("ASCII", new JScrollPane(asciiArea));

        JPanel detailsPanel = new JPanel(new BorderLayout());
        detailsPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(BORDER_COLOR), "Selected Packet"));
        detailsPanel.add(detailsTabs, BorderLayout.CENTER);

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, packetScrollPane, detailsPanel);
        splitPane.setResizeWeight(0.62);
        splitPane.setDividerLocation(0.62);

        JPanel statusBar = new JPanel(new BorderLayout());
        statusBar.setBorder(BorderFactory.createEmptyBorder(0, 10, 8, 10));
        statusBar.add(statusLabel, BorderLayout.WEST);

        add(topBar, BorderLayout.NORTH);
        add(splitPane, BorderLayout.CENTER);
        add(statusBar, BorderLayout.SOUTH);

        applyPinkTheme(topBar, packetScrollPane, detailsPanel, detailsTabs, statusBar);
    }

    private void wireEvents() {
        refreshButton.addActionListener(event -> refreshInterfaces());
        startButton.addActionListener(event -> startCapture());
        stopButton.addActionListener(event -> stopCapture());
        clearButton.addActionListener(event -> clearPackets());
        exportNoteButton.addActionListener(event -> exportSelectedPacketNote());

        ListSelectionListener selectionListener = event -> {
            if (!event.getValueIsAdjusting()) {
                updateSelectedPacketDetails();
            }
        };
        packetTable.getSelectionModel().addListSelectionListener(selectionListener);
    }

    /**
     * Loads interfaces into the selector for user capture selection.
     */
    private void refreshInterfaces() {
        try {
            List<PcapNetworkInterface> interfaces = captureController.listInterfaces();
            interfaceModel.removeAllElements();
            for (PcapNetworkInterface networkInterface : interfaces) {
                interfaceModel.addElement(networkInterface);
            }
            statusLabel.setText("Found " + interfaces.size() + " interface(s).");
        } catch (RuntimeException exception) {
            showError("Unable to list network interfaces.", exception);
        }
    }

    /**
     * Starts capture on the currently selected interface.
     */
    private void startCapture() {
        PcapNetworkInterface selectedInterface = (PcapNetworkInterface) interfaceComboBox.getSelectedItem();
        if (selectedInterface == null) {
            JOptionPane.showMessageDialog(this,
                    "Select an interface before starting capture.",
                    "No Interface",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        clearPackets();
        try {
            captureController.startCapture(selectedInterface, this);
            interfaceComboBox.setEnabled(false);
            refreshButton.setEnabled(false);
            startButton.setEnabled(false);
            stopButton.setEnabled(true);
            statusLabel.setText("Capturing on " + selectedInterface.getName() + "...");
        } catch (RuntimeException exception) {
            showError("Unable to start live capture.", exception);
        }
    }

    private void stopCapture() {
        captureController.stopCapture();
        restoreIdleState();
        statusLabel.setText("Capture stopped.");
    }

    private void clearPackets() {
        packets.clear();
        tableModel.setRowCount(0);
        decodeArea.setText("");
        hexArea.setText("");
        asciiArea.setText("");
    }

    private void updateSelectedPacketDetails() {
        int selectedViewRow = packetTable.getSelectedRow();
        if (selectedViewRow < 0) {
            decodeArea.setText("");
            hexArea.setText("");
            asciiArea.setText("");
            return;
        }

        int modelRow = packetTable.convertRowIndexToModel(selectedViewRow);
        if (modelRow < 0 || modelRow >= packets.size()) {
            return;
        }

        CapturedPacket packet = packets.get(modelRow);
        decodeArea.setText(packet.getDecodeText());
        decodeArea.setCaretPosition(0);
        hexArea.setText(packet.getHexDump());
        hexArea.setCaretPosition(0);
        asciiArea.setText(PacketFormatter.toSafeAscii(packet.getRawBytes()));
        asciiArea.setCaretPosition(0);
    }

    @Override
    public void onPacketCaptured(CapturedPacket packet) {
        SwingUtilities.invokeLater(() -> {
            packets.add(packet);
            tableModel.addRow(new Object[]{
                    packet.getIndex(),
                    packet.getDisplayTime(),
                    TIME_FORMAT.format(packet.getRelativeTimeSeconds()),
                    TIME_FORMAT.format(packet.getDeltaTimeSeconds()),
                    packet.getDirection(),
                    packet.getSource(),
                    packet.getDestination(),
                    packet.getProtocol(),
                    packet.getLength(),
                    packet.getFlow(),
                    packet.getInfo()
            });
            int lastRow = tableModel.getRowCount() - 1;
            if (lastRow >= 0) {
                int viewRow = packetTable.convertRowIndexToView(lastRow);
                if (viewRow >= 0) {
                    packetTable.getSelectionModel().setSelectionInterval(viewRow, viewRow);
                    packetTable.scrollRectToVisible(packetTable.getCellRect(viewRow, 0, true));
                }
            }
            statusLabel.setText("Captured " + tableModel.getRowCount() + " packet(s).");
        });
    }

    @Override
    public void onCaptureStarted(String interfaceName) {
        SwingUtilities.invokeLater(() -> statusLabel.setText("Capturing on " + interfaceName + "..."));
    }

    @Override
    public void onCaptureStopped() {
        SwingUtilities.invokeLater(() -> {
            restoreIdleState();
            statusLabel.setText("Capture stopped.");
        });
    }

    @Override
    public void onCaptureError(String message, Exception exception) {
        SwingUtilities.invokeLater(() -> {
            restoreIdleState();
            showError(message, exception);
        });
    }

    private void restoreIdleState() {
        interfaceComboBox.setEnabled(true);
        refreshButton.setEnabled(true);
        startButton.setEnabled(true);
        stopButton.setEnabled(false);
    }

    private void showError(String message, Exception exception) {
        statusLabel.setText(message);
        JOptionPane.showMessageDialog(this,
                message + System.lineSeparator() + exception.getMessage(),
                "LilSniff Error",
                JOptionPane.ERROR_MESSAGE);
    }

    private void applyPinkTheme(JPanel topBar,
                                JScrollPane packetScrollPane,
                                JPanel detailsPanel,
                                JTabbedPane detailsTabs,
                                JPanel statusBar) {
        getContentPane().setBackground(BG_BASE);
        topBar.setBackground(BG_PANEL);
        packetScrollPane.getViewport().setBackground(BG_BASE);
        detailsPanel.setBackground(BG_BASE);
        detailsTabs.setBackground(BG_PANEL);
        statusBar.setBackground(BG_PANEL);
        statusLabel.setForeground(TEXT_COLOR);

        interfaceComboBox.setBackground(Color.WHITE);
        interfaceComboBox.setForeground(TEXT_COLOR);
        styleButton(refreshButton);
        styleButton(startButton);
        styleButton(stopButton);
        styleButton(clearButton);
        styleButton(exportNoteButton);

        packetTable.setBackground(BG_BASE);
        packetTable.setForeground(TEXT_COLOR);
        packetTable.setGridColor(BORDER_COLOR);
        packetTable.setSelectionBackground(BG_SELECTION);
        packetTable.setSelectionForeground(Color.BLACK);
        packetTable.getTableHeader().setBackground(BG_PANEL);
        packetTable.getTableHeader().setForeground(TEXT_COLOR);
    }

    private void styleButton(JButton button) {
        button.setBackground(BG_PANEL);
        button.setForeground(TEXT_COLOR);
        button.setBorder(BorderFactory.createLineBorder(BORDER_COLOR));
        button.setFocusPainted(false);
    }

    private void setupLogoLabel() {
        ImageIcon icon = loadLogoIcon(43);
        if (icon != null) {
            logoLabel.setIcon(icon);
        } else {
            logoLabel.setText("LilSniff");
            logoLabel.setForeground(TEXT_COLOR);
        }
        logoLabel.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 8));
    }

    private ImageIcon loadLogoIcon(int size) {
        java.net.URL resource = getClass().getResource("/assets/lilsniff-logo.png");
        if (resource == null) {
            return null;
        }
        ImageIcon original = new ImageIcon(resource);
        Image scaled = original.getImage().getScaledInstance(size, size, Image.SCALE_SMOOTH);
        return new ImageIcon(scaled);
    }

    private static JTextArea createReadOnlyTextArea() {
        JTextArea area = new JTextArea();
        area.setEditable(false);
        area.setFont(new java.awt.Font("Consolas", java.awt.Font.PLAIN, 12));
        area.setBackground(BG_BASE);
        area.setForeground(TEXT_COLOR);
        return area;
    }

    private static final class PacketTableRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table,
                                                       Object value,
                                                       boolean isSelected,
                                                       boolean hasFocus,
                                                       int row,
                                                       int column) {
            Component component = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (!isSelected) {
                component.setBackground(row % 2 == 0 ? BG_BASE : BG_TABLE_ALT);
                component.setForeground(TEXT_COLOR);
            }
            return component;
        }
    }

    /**
     * Exports the selected packet details to a text note.
     */
    private void exportSelectedPacketNote() {
        int selectedViewRow = packetTable.getSelectedRow();
        if (selectedViewRow < 0) {
            JOptionPane.showMessageDialog(this,
                    "Select a packet first, then export.",
                    "No Packet Selected",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        int modelRow = packetTable.convertRowIndexToModel(selectedViewRow);
        if (modelRow < 0 || modelRow >= packets.size()) {
            JOptionPane.showMessageDialog(this,
                    "Unable to resolve selected packet.",
                    "Selection Error",
                    JOptionPane.ERROR_MESSAGE);
            return;
        }

        CapturedPacket packet = packets.get(modelRow);

        javax.swing.JFileChooser fileChooser = new javax.swing.JFileChooser();
        fileChooser.setDialogTitle("Export Packet Note");
        fileChooser.setFileFilter(new FileNameExtensionFilter("Text Note (*.txt)", "txt"));
        fileChooser.setSelectedFile(new java.io.File("lilsniff-packet-" + packet.getIndex() + ".txt"));

        int result = fileChooser.showSaveDialog(this);
        if (result != javax.swing.JFileChooser.APPROVE_OPTION) {
            return;
        }

        Path filePath = fileChooser.getSelectedFile().toPath();
        if (!filePath.toString().toLowerCase().endsWith(".txt")) {
            filePath = Path.of(filePath.toString() + ".txt");
        }

        String noteText = buildPacketNote(packet);
        try {
            Files.writeString(filePath, noteText);
            statusLabel.setText("Exported note: " + filePath.getFileName());
        } catch (IOException exception) {
            showError("Unable to export packet note.", exception);
        }
    }

    private String buildPacketNote(CapturedPacket packet) {
        return "LilSniff Packet Note" + System.lineSeparator()
                + "===================" + System.lineSeparator()
                + "Packet #: " + packet.getIndex() + System.lineSeparator()
                + "Time: " + packet.getDisplayTime() + System.lineSeparator()
                + String.format("Relative Time: %.6f s%n", packet.getRelativeTimeSeconds())
                + String.format("Delta Time: %.6f s%n", packet.getDeltaTimeSeconds())
                + "Direction: " + packet.getDirection() + System.lineSeparator()
                + "Source: " + packet.getSource() + System.lineSeparator()
                + "Destination: " + packet.getDestination() + System.lineSeparator()
                + "Protocol: " + packet.getProtocol() + System.lineSeparator()
                + "App Hint: " + packet.getAppProtocol() + System.lineSeparator()
                + "Length: " + packet.getLength() + " bytes" + System.lineSeparator()
                + "Flow: " + packet.getFlow() + System.lineSeparator()
                + "Info: " + packet.getInfo() + System.lineSeparator()
                + System.lineSeparator()
                + "Decoded Details" + System.lineSeparator()
                + "---------------" + System.lineSeparator()
                + packet.getDecodeText() + System.lineSeparator()
                + System.lineSeparator()
                + "Hex Dump" + System.lineSeparator()
                + "--------" + System.lineSeparator()
                + packet.getHexDump() + System.lineSeparator();
    }
}
