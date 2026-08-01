/**
 * App shell. Boots the VaultRuntime, listens for connection-consent requests (and
 * shows the ApprovalSheet over whatever is on screen), and provides simple tab
 * navigation between Vault / Connect / Connections. Real deep-link handling (for
 * Universal Links) is wired via expo-linking.
 */

import "react-native-get-random-values";
import React, { useEffect, useRef, useState } from "react";
import { View, Text, Pressable, StyleSheet, ActivityIndicator } from "react-native";
import { StatusBar } from "expo-status-bar";
import * as Linking from "expo-linking";
import { VaultRuntime } from "./src/runtime/VaultRuntime";
import type { PendingConsent } from "./src/runtime/consent";
import { Onboarding } from "./src/screens/Onboarding";
import { Scan } from "./src/screens/Scan";
import { Connections } from "./src/screens/Connections";
import { ApprovalSheet } from "./src/screens/ApprovalSheet";

const RELAY_URL = process.env.EXPO_PUBLIC_RELAY_URL ?? "wss://relay.vault.app";

type Tab = "connections" | "connect";

export default function App() {
  const [runtime, setRuntime] = useState<VaultRuntime | null>(null);
  const [onboarded, setOnboarded] = useState(false);
  const [tab, setTab] = useState<Tab>("connections");
  const [pending, setPending] = useState<PendingConsent | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const runtimeRef = useRef<VaultRuntime | null>(null);

  useEffect(() => {
    VaultRuntime.create({ relayUrl: RELAY_URL }).then((rt) => {
      rt.consent.onRequest((p) => setPending(p));
      runtimeRef.current = rt;
      setRuntime(rt);
    });
  }, []);

  useEffect(() => {
    const sub = Linking.addEventListener("url", ({ url }) => {
      if (url.includes("/pair") || url.startsWith("vault:")) void runtimeRef.current?.pair(toPairingUri(url));
    });
    return () => sub.remove();
  }, []);

  if (!runtime) {
    return (
      <View style={styles.boot}>
        <ActivityIndicator color="#2dd4bf" />
        <Text style={styles.bootText}>Opening your vault…</Text>
      </View>
    );
  }

  if (!onboarded) return <Onboarding onComplete={() => setOnboarded(true)} />;

  return (
    <View style={styles.app}>
      <StatusBar style="light" />
      <View style={styles.header}>
        <Text style={styles.brand}>VAULT</Text>
      </View>

      <View style={styles.body}>
        {tab === "connections" && (
          <Connections runtime={runtime} refreshKey={refreshKey} onRevoke={() => setRefreshKey((k) => k + 1)} />
        )}
        {tab === "connect" && <Scan runtime={runtime} onPaired={() => setTab("connections")} />}
      </View>

      <View style={styles.tabs}>
        <TabButton label="Connections" active={tab === "connections"} onPress={() => setTab("connections")} />
        <TabButton label="+ Connect" active={tab === "connect"} onPress={() => setTab("connect")} />
      </View>

      {pending && (
        <ApprovalSheet
          pending={pending}
          onDone={() => {
            setPending(null);
            setRefreshKey((k) => k + 1);
          }}
        />
      )}
    </View>
  );
}

function TabButton({ label, active, onPress }: { label: string; active: boolean; onPress: () => void }) {
  return (
    <Pressable style={styles.tab} onPress={onPress}>
      <Text style={[styles.tabText, active && styles.tabActive]}>{label}</Text>
    </Pressable>
  );
}

/** Universal Link (`https://vault.app/pair?...`) → `vault:` pairing URI. */
function toPairingUri(url: string): string {
  if (url.startsWith("vault:")) return url;
  const u = new URL(url);
  return `vault:${u.searchParams.get("topic")}@${u.searchParams.get("v") ?? "1"}?${u.search.slice(1)}`;
}

const styles = StyleSheet.create({
  boot: { flex: 1, backgroundColor: "#0b0e13", alignItems: "center", justifyContent: "center", gap: 12 },
  bootText: { color: "#9aa4b2" },
  app: { flex: 1, backgroundColor: "#0b0e13" },
  header: { paddingTop: 60, paddingBottom: 16, paddingHorizontal: 20, borderBottomWidth: 1, borderBottomColor: "#232a34" },
  brand: { color: "#2dd4bf", fontSize: 22, fontWeight: "800", letterSpacing: 2 },
  body: { flex: 1 },
  tabs: { flexDirection: "row", borderTopWidth: 1, borderTopColor: "#232a34", paddingBottom: 24 },
  tab: { flex: 1, padding: 16, alignItems: "center" },
  tabText: { color: "#6f7885", fontWeight: "600" },
  tabActive: { color: "#2dd4bf" },
});
