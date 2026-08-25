import { useCallback, useEffect, useState } from "react";
import type { X25519Keypair } from "../lib/crypto";
import { generateBuyerKeypair } from "../lib/crypto";
import {
  clearKeySession,
  loadKeyFromSession,
  parseBackup,
  saveKeyToSession,
} from "../lib/backup";

// The buyer's X25519 keypair for the active session: kept in sessionStorage
// (survives navigation, cleared on tab close), restorable from a backup file.
export function useBuyerKey() {
  const [keypair, setKeypair] = useState<X25519Keypair | null>(null);

  useEffect(() => {
    setKeypair(loadKeyFromSession());
  }, []);

  const generate = useCallback(async () => {
    const kp = await generateBuyerKeypair();
    saveKeyToSession(kp);
    setKeypair(kp);
    return kp;
  }, []);

  // Restore from a backup file's JSON contents; throws with a specific message
  // if the file is not a valid, self-consistent backup.
  const restore = useCallback(async (json: string) => {
    const kp = await parseBackup(json);
    saveKeyToSession(kp);
    setKeypair(kp);
    return kp;
  }, []);

  const clear = useCallback(() => {
    clearKeySession();
    setKeypair(null);
  }, []);

  return { keypair, generate, restore, clear };
}
