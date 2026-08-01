/**
 * Scan — the pairing entry point. Scans a `vault:` pairing QR with the camera and
 * hands the URI to the runtime. On a Universal Link (`https://vault.app/pair?…`)
 * the OS routes straight here without the camera.
 */

import React, { useState } from "react";
import { View, Text, StyleSheet, Pressable } from "react-native";
import { CameraView, useCameraPermissions } from "expo-camera";
import type { VaultRuntime } from "../runtime/VaultRuntime";

export function Scan({ runtime, onPaired }: { runtime: VaultRuntime; onPaired: () => void }) {
  const [permission, requestPermission] = useCameraPermissions();
  const [busy, setBusy] = useState(false);

  if (!permission?.granted) {
    return (
      <View style={styles.center}>
        <Text style={styles.text}>Camera access is needed to scan pairing codes.</Text>
        <Pressable style={styles.btn} onPress={requestPermission}>
          <Text style={styles.btnText}>Grant camera access</Text>
        </Pressable>
      </View>
    );
  }

  async function onScan(data: string) {
    if (busy || !data.startsWith("vault:")) return;
    setBusy(true);
    try {
      await runtime.pair(data);
      onPaired();
    } finally {
      setBusy(false);
    }
  }

  return (
    <View style={StyleSheet.absoluteFill}>
      <CameraView
        style={StyleSheet.absoluteFill}
        barcodeScannerSettings={{ barcodeTypes: ["qr"] }}
        onBarcodeScanned={({ data }) => void onScan(data)}
      />
      <View style={styles.hint}>
        <Text style={styles.text}>Point at a Vault pairing QR</Text>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  center: { flex: 1, alignItems: "center", justifyContent: "center", gap: 16, padding: 24, backgroundColor: "#0b0e13" },
  hint: { position: "absolute", bottom: 60, alignSelf: "center", backgroundColor: "rgba(0,0,0,0.6)", padding: 12, borderRadius: 10 },
  text: { color: "#e7ebf0", textAlign: "center" },
  btn: { backgroundColor: "#0f766e", padding: 14, borderRadius: 12 },
  btnText: { color: "white", fontWeight: "700" },
});
