package com.lilsniff;

import com.lilsniff.capture.CaptureController;
import com.lilsniff.ui.MainFrame;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;

/**
 * Application entry point for LilSniff.
 * Initializes Swing look and feel, capture controller, and main window.
 */
public final class LilSniffApp {

    private LilSniffApp() {
    }

    /**
     * Launches the LilSniff desktop UI.
     */
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            applySystemLookAndFeel();
            CaptureController captureController = new CaptureController();
            MainFrame frame = new MainFrame(captureController);
            frame.setVisible(true);
        });
    }

    /**
     * Uses the host system look and feel when available.
     */
    private static void applySystemLookAndFeel() {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception ignored) {
            // Keep Swing defaults if system L&F is unavailable.
        }
    }
}
