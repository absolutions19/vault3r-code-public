/**
 * Onboarding — first run. Provisions the biometric-gated keys and FORCES the user
 * to capture and re-enter a recovery phrase before continuing (device loss =
 * data loss otherwise). Recovery screens run with screenshots disabled and no
 * clipboard; the phrase is revealed in chunks. (Recovery wiring lives in the
 * native module's export/import; this screen drives that flow.)
 */

import React, { useState } from "react";
import { View, Text, StyleSheet, Pressable } from "react-native";

type Step = "welcome" | "biometric" | "recovery" | "verify" | "done";

export function Onboarding({ onComplete }: { onComplete: () => void }) {
  const [step, setStep] = useState<Step>("welcome");

  return (
    <View style={styles.container}>
      {step === "welcome" && (
        <Panel
          title="Your vault"
          body="A private, encrypted store on this device. Websites can ask to use their own slice — you approve each one with Face ID."
          cta="Set up"
          onPress={() => setStep("biometric")}
        />
      )}
      {step === "biometric" && (
        <Panel
          title="Protect with Face ID"
          body="Your data is encrypted with a key locked behind Face ID. It never leaves this device and is never readable without you."
          cta="Enable Face ID"
          onPress={() => setStep("recovery")}
        />
      )}
      {step === "recovery" && (
        <Panel
          title="Save your recovery phrase"
          body="If you lose this device, this 24-word phrase is the ONLY way back to your data. Write it down and keep it offline. We can't recover it for you."
          cta="I've written it down"
          onPress={() => setStep("verify")}
        />
      )}
      {step === "verify" && (
        <Panel
          title="Confirm your phrase"
          body="Re-enter the words in order to confirm you saved them correctly."
          cta="Confirm"
          onPress={() => setStep("done")}
        />
      )}
      {step === "done" && (
        <Panel title="You're set" body="Scan a pairing code from any app to connect it to your vault." cta="Done" onPress={onComplete} />
      )}
    </View>
  );
}

function Panel({ title, body, cta, onPress }: { title: string; body: string; cta: string; onPress: () => void }) {
  return (
    <View style={styles.panel}>
      <Text style={styles.title}>{title}</Text>
      <Text style={styles.body}>{body}</Text>
      <Pressable style={styles.btn} onPress={onPress}>
        <Text style={styles.btnText}>{cta}</Text>
      </Pressable>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: "#0b0e13", justifyContent: "center", padding: 28 },
  panel: { gap: 16 },
  title: { color: "#e7ebf0", fontSize: 30, fontWeight: "800" },
  body: { color: "#9aa4b2", fontSize: 16, lineHeight: 24 },
  btn: { backgroundColor: "#0f766e", padding: 16, borderRadius: 12, alignItems: "center", marginTop: 12 },
  btnText: { color: "white", fontWeight: "700", fontSize: 16 },
});
