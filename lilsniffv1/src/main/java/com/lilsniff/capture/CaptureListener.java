package com.lilsniff.capture;

import com.lilsniff.model.CapturedPacket;

/**
 * Listener contract used by {@link CaptureController} to push capture updates to the UI.
 */
public interface CaptureListener {

    /**
     * Called each time a packet is captured and converted into UI-friendly data.
     */
    void onPacketCaptured(CapturedPacket packet);

    /**
     * Called when live capture starts.
     */
    void onCaptureStarted(String interfaceName);

    /**
     * Called when capture stops normally or after cleanup.
     */
    void onCaptureStopped();

    /**
     * Called when capture fails while starting or during packet polling.
     */
    void onCaptureError(String message, Exception exception);
}
