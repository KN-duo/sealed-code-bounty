import { PublicKey } from "@solana/web3.js";
import { Connection } from "@solana/web3.js";

const CLOCK_SYSVAR = new PublicKey(
  "SysvarC1ock11111111111111111111111111111111"
);

/**
 * Chain-clock seconds read straight from the Clock sysvar — the exact value
 * Clock::get() hands programs. NOTE the Agave field order:
 *   slot(0) · epoch_start_timestamp(8) · epoch(16) ·
 *   leader_schedule_epoch(24) · unix_timestamp(32)
 */
export async function chainClock(connection: Connection): Promise<number> {
  const info = await connection.getAccountInfo(CLOCK_SYSVAR);
  if (!info || info.data.length < 40) {
    return Math.floor(Date.now() / 1000);
  }
  return Number(info.data.readBigInt64LE(32));
}
