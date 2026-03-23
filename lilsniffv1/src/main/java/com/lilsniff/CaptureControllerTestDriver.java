package com.lilsniff;

import com.lilsniff.capture.CaptureController;
import java.util.List;
import org.pcap4j.core.PcapNetworkInterface;

/**
 * Simple console driver for initial Phase 2 testing.
 * Verifies that interface listing works and controller resources shut down cleanly.
 */
public final class CaptureControllerTestDriver {

    private CaptureControllerTestDriver() {
    }

    public static void main(String[] args) {
        CaptureController controller = new CaptureController();
        try {
            List<PcapNetworkInterface> interfaces = controller.listInterfaces();

            System.out.println("LilSniff Initial Test");
            System.out.println("---------------------");
            System.out.println("Interfaces found: " + interfaces.size());

            for (int index = 0; index < interfaces.size(); index++) {
                PcapNetworkInterface networkInterface = interfaces.get(index);
                String description = networkInterface.getDescription();
                System.out.println((index + 1) + ". " + networkInterface.getName()
                        + (description == null || description.isBlank() ? "" : " - " + description));
            }

            System.out.println("Interface listing test completed successfully.");
        } catch (Exception exception) {
            System.err.println("Test failed: " + exception.getMessage());
            exception.printStackTrace();
        } finally {
            controller.shutdown();
        }
    }
}
