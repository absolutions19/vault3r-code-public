/**
 * ApprovalSheet — the UI *is* the security boundary.
 *
 * The verified domain + derived namespace are the visual hero. The caller's own
 * name/icon are always demoted and badged "claimed — not verified". Consent is
 * per-field (optionals default off), and the user must confirm the number-match
 * code shown in the browser (anti pairing-relay phishing). Nothing is granted
 * until the user approves AND passes biometric (enforced by the engine).
 */

import React, { useMemo, useState } from "react";
import { View, Text, Switch, Pressable, StyleSheet, ScrollView } from "react-native";
import type { PendingConsent } from "../runtime/consent";
import type { FieldRule, TrustTier } from "@vault/protocol";

const TIER_META: Record<TrustTier, { label: string; color: string; note: string }> = {
  verified: { label: "VERIFIED", color: "#15803d", note: "Domain proven via TLS-served identity" },
  "look-alike": { label: "LOOK-ALIKE", color: "#b45309", note: "This domain resembles one you trust — check it carefully" },
  unverified: { label: "UNVERIFIED", color: "#b3251f", note: "Identity could not be verified — access is isolated" },
  threat: { label: "THREAT", color: "#7f1d1d", note: "Known-malicious — do not connect" },
};

export function ApprovalSheet({ pending, onDone }: { pending: PendingConsent; onDone: () => void }) {
  const { request, resolve } = pending;
  const v = request.verification;
  const tier = TIER_META[v.tier];
  const requestedFields = useMemo(() => request.requestedScopes.flatMap((s) => s.fields), [request]);
  const [grants, setGrants] = useState<Record<string, boolean>>(
    Object.fromEntries(requestedFields.map((f) => [f.path, !isOptional(f)])),
  );

  const canConnect = v.tier !== "threat";

  function decide(approved: boolean) {
    if (!approved) {
      resolve({ approved: false, reason: "user declined" });
      return onDone();
    }
    const grantedFields = requestedFields.filter((f) => grants[f.path]);
    resolve({ approved: true, grantedFields });
    onDone();
  }

  return (
    <View style={styles.overlay}>
      <ScrollView contentContainerStyle={styles.sheet}>
        <View style={[styles.tier, { backgroundColor: tier.color }]}>
          <Text style={styles.tierLabel}>{tier.label}</Text>
        </View>

        <Text style={styles.hero}>{v.domain ?? "unknown"}</Text>
        <Text style={styles.namespace}>namespace: {v.namespace}</Text>
        <Text style={styles.tierNote}>{tier.note}</Text>

        <View style={styles.claimed}>
          <Text style={styles.claimedBadge}>claimed — not verified</Text>
          <Text style={styles.claimedName}>{request.appMetadata.name ?? "(no name)"}</Text>
        </View>

        <Text style={styles.section}>Requested access</Text>
        {requestedFields.map((f) => (
          <View key={f.path} style={styles.fieldRow}>
            <View style={{ flex: 1 }}>
              <Text style={styles.fieldPath}>{f.path}</Text>
              <Text style={styles.fieldBits}>
                {f.read ? "read" : ""}
                {f.read && f.write ? " · " : ""}
                {f.write ? "write" : ""}
                {f.sensitive ? "  🔒 sensitive" : ""}
              </Text>
            </View>
            <Switch value={!!grants[f.path]} onValueChange={(val) => setGrants((g) => ({ ...g, [f.path]: val }))} />
          </View>
        ))}

        <View style={styles.matchBox}>
          <Text style={styles.matchLabel}>Confirm this code matches your browser</Text>
          <Text style={styles.matchCode}>{formatCode(request.pairingChallenge)}</Text>
          {request.assertedAccount ? <Text style={styles.account}>linking account: {request.assertedAccount}</Text> : null}
        </View>

        <View style={styles.actions}>
          <Pressable style={[styles.btn, styles.reject]} onPress={() => decide(false)}>
            <Text style={styles.btnText}>Reject</Text>
          </Pressable>
          <Pressable
            style={[styles.btn, styles.approve, !canConnect && styles.disabled]}
            disabled={!canConnect}
            onPress={() => decide(true)}
          >
            <Text style={styles.btnText}>Approve with Face ID</Text>
          </Pressable>
        </View>
      </ScrollView>
    </View>
  );
}

function isOptional(f: FieldRule): boolean {
  return !f.read && !f.write;
}
function formatCode(code: string): string {
  return code.replace(/(\d{4})(\d{4})/, "$1 $2");
}

const styles = StyleSheet.create({
  overlay: { ...StyleSheet.absoluteFillObject, backgroundColor: "rgba(0,0,0,0.5)", justifyContent: "flex-end" },
  sheet: { backgroundColor: "#12161c", padding: 24, borderTopLeftRadius: 20, borderTopRightRadius: 20, gap: 6 },
  tier: { alignSelf: "flex-start", paddingHorizontal: 10, paddingVertical: 4, borderRadius: 6, marginBottom: 8 },
  tierLabel: { color: "white", fontWeight: "700", fontSize: 12, letterSpacing: 1 },
  hero: { color: "#e7ebf0", fontSize: 28, fontWeight: "800" },
  namespace: { color: "#2dd4bf", fontFamily: "Menlo", fontSize: 13 },
  tierNote: { color: "#9aa4b2", fontSize: 13, marginTop: 4 },
  claimed: { flexDirection: "row", alignItems: "center", gap: 8, marginTop: 12 },
  claimedBadge: { color: "#b45309", fontSize: 10, borderWidth: 1, borderColor: "#b45309", borderRadius: 4, padding: 2 },
  claimedName: { color: "#6f7885", fontStyle: "italic" },
  section: { color: "#e7ebf0", fontSize: 14, fontWeight: "700", marginTop: 20, marginBottom: 6 },
  fieldRow: { flexDirection: "row", alignItems: "center", paddingVertical: 8, borderBottomWidth: 1, borderBottomColor: "#232a34" },
  fieldPath: { color: "#e7ebf0", fontFamily: "Menlo", fontSize: 14 },
  fieldBits: { color: "#9aa4b2", fontSize: 12 },
  matchBox: { marginTop: 20, padding: 14, backgroundColor: "#10312d", borderRadius: 10 },
  matchLabel: { color: "#9aa4b2", fontSize: 12 },
  matchCode: { color: "#2dd4bf", fontSize: 30, fontWeight: "800", letterSpacing: 4, fontFamily: "Menlo" },
  account: { color: "#9aa4b2", fontSize: 12, marginTop: 4 },
  actions: { flexDirection: "row", gap: 12, marginTop: 24 },
  btn: { flex: 1, padding: 16, borderRadius: 12, alignItems: "center" },
  reject: { backgroundColor: "#232a34" },
  approve: { backgroundColor: "#0f766e" },
  disabled: { opacity: 0.4 },
  btnText: { color: "white", fontWeight: "700" },
});
