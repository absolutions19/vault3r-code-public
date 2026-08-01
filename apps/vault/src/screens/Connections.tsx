/**
 * Connections — the connected-apps manager. Lists each session's verified domain,
 * derived namespace, and granted fields, and lets the user revoke access with one
 * tap. Verified identity is always the hero; the app's claimed name is secondary.
 */

import React from "react";
import { View, Text, FlatList, Pressable, StyleSheet } from "react-native";
import type { VaultRuntime } from "../runtime/VaultRuntime";

export function Connections({ runtime, refreshKey, onRevoke }: { runtime: VaultRuntime; refreshKey: number; onRevoke: () => void }) {
  const connections = runtime.engine.listConnections();

  if (connections.length === 0) {
    return (
      <View style={styles.empty}>
        <Text style={styles.emptyText}>No connected apps yet.</Text>
        <Text style={styles.emptyHint}>Scan a pairing code to connect one.</Text>
      </View>
    );
  }

  return (
    <FlatList
      style={styles.list}
      data={connections}
      keyExtractor={(c) => c.sessionId}
      extraData={refreshKey}
      renderItem={({ item }) => (
        <View style={styles.card}>
          <View style={styles.rowTop}>
            <Text style={styles.domain}>{item.grant.domain ?? "unverified"}</Text>
            {item.grant.verified ? <Text style={styles.verified}>✓ verified</Text> : <Text style={styles.unverified}>unverified</Text>}
          </View>
          <Text style={styles.namespace}>{item.grant.namespace}</Text>
          <Text style={styles.fields}>
            {item.grant.fields.map((f) => `${f.path}${f.write ? " (rw)" : " (r)"}`).join("  ·  ")}
          </Text>
          <Pressable
            style={styles.revoke}
            onPress={() => {
              runtime.engine.adminRevoke(item.sessionId);
              onRevoke();
            }}
          >
            <Text style={styles.revokeText}>Revoke access</Text>
          </Pressable>
        </View>
      )}
    />
  );
}

const styles = StyleSheet.create({
  list: { flex: 1, backgroundColor: "#0b0e13" },
  empty: { flex: 1, alignItems: "center", justifyContent: "center", backgroundColor: "#0b0e13", gap: 6 },
  emptyText: { color: "#e7ebf0", fontSize: 16 },
  emptyHint: { color: "#6f7885" },
  card: { margin: 12, padding: 16, backgroundColor: "#12161c", borderRadius: 12, gap: 6 },
  rowTop: { flexDirection: "row", justifyContent: "space-between", alignItems: "center" },
  domain: { color: "#e7ebf0", fontSize: 18, fontWeight: "700" },
  verified: { color: "#4ade80", fontSize: 12 },
  unverified: { color: "#f87171", fontSize: 12 },
  namespace: { color: "#2dd4bf", fontFamily: "Menlo", fontSize: 12 },
  fields: { color: "#9aa4b2", fontSize: 12 },
  revoke: { marginTop: 8, alignSelf: "flex-start", paddingHorizontal: 12, paddingVertical: 6, borderRadius: 8, backgroundColor: "#35191a" },
  revokeText: { color: "#f87171", fontWeight: "600" },
});
