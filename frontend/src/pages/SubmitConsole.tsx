import { useEffect, useRef, useState } from "react";
import { useWallet } from "@solana/wallet-adapter-react";
import { WalletMultiButton } from "@solana/wallet-adapter-react-ui";
import { PublicKey } from "@solana/web3.js";
import {
  ArrowLeft,
  CheckCircle2,
  Crosshair,
  PartyPopper,
  ShieldAlert,
  Terminal,
  XCircle,
} from "lucide-react";
import { AsyncView } from "../components/ui/states";
import { Card, Mono, SolAmount } from "../components/ui/atoms";
import { Button } from "../components/ui/Button";
import { FileDrop, Field, Textarea } from "../components/ui/forms";
import { HashBadge } from "../components/ui/HashBadge";
import { Link } from "../router";
import { useBounty, useConfig } from "../hooks/useData";
import { useProgram } from "../hooks/useProgram";
import { useToast } from "../components/ui/Toast";
import {
  buildSubmitIntentMessage,
  sealTo,
  sha256Bytes,
  toBase64,
} from "../lib/crypto";
import { bytesToHex } from "../lib/format";
import { fetchBounty } from "../lib/anchorClient";
import { uploadExploit } from "../lib/runner";
import { submitExploit, txErrorMessage } from "../lib/tx";
import type { Bounty, ProtocolConfig } from "../lib/types";

type Phase = "compose" | "working" | "watching" | "pass" | "fail";
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export function SubmitConsole({ pda }: { pda: string }) {
  const wallet = useWallet();
  const program = useProgram();
  const toast = useToast();
  const bounty = useBounty(pda);
  const config = useConfig();

  if (!wallet.publicKey) {
    return (
      <Card style={{ padding: 40, textAlign: "center" }} className="stack">
        <ShieldAlert size={34} className="dim" style={{ margin: "0 auto" }} />
        <h2>Connect a wallet to submit an exploit</h2>
        <p className="dim">You'll sign an intent proof and pay a refundable bond.</p>
        <div style={{ margin: "0 auto" }}>
          <WalletMultiButton />
        </div>
      </Card>
    );
  }

  return (
    <div className="stack" style={{ gap: 20, maxWidth: 760, margin: "0 auto" }}>
      <Link to={`/bounty/${pda}`} className="row dim backlink">
        <ArrowLeft size={16} /> Back to bounty
      </Link>
      <AsyncView
        state={bounty.state}
        onRetry={bounty.reload}
        emptyTitle="Bounty not found"
        emptyMessage="No bounty exists at this address on the current cluster."
      >
        {(b) => (
          <Console
            bounty={b}
            config={config.state.kind === "success" ? config.state.data : null}
            solver={wallet.publicKey!}
            signMessage={wallet.signMessage}
            submit={async (blobUrl, exploitSha) => {
              if (!program) throw new Error("Wallet program unavailable.");
              return submitExploit(program, wallet.publicKey!, new PublicKey(b.pda), {
                bountyId: b.bountyId,
                blobUrl,
                exploitSha256: exploitSha,
              });
            }}
            toast={toast}
          />
        )}
      </AsyncView>
    </div>
  );
}

interface ConsoleProps {
  bounty: Bounty;
  config: ProtocolConfig | null;
  solver: PublicKey;
  signMessage?: (msg: Uint8Array) => Promise<Uint8Array>;
  submit: (blobUrl: string, exploitSha256: Uint8Array) => Promise<string>;
  toast: { push: (m: string, k?: "success" | "error" | "info") => void };
}

function Console({ bounty, config, solver, signMessage, submit, toast }: ConsoleProps) {
  const [phase, setPhase] = useState<Phase>("compose");
  const [source, setSource] = useState("");
  const [fileName, setFileName] = useState<string | null>(null);
  const [log, setLog] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [txSig, setTxSig] = useState<string | null>(null);
  const watching = useRef(false);

  const addLog = (line: string) => setLog((l) => [...l, line]);

  const notOpen = bounty.status !== "open";
  const canSign = typeof signMessage === "function";

  // Poll on-chain status after submission until a terminal verdict.
  useEffect(() => {
    if (phase !== "watching") return;
    watching.current = true;
    (async () => {
      for (let i = 0; i < 40 && watching.current; i++) {
        await sleep(3000);
        let b: Bounty | null = null;
        try {
          b = await fetchBounty(bounty.pda);
        } catch {
          continue; // transient RPC hiccup; keep polling
        }
        if (!b) continue;
        if (b.status === "resolved") {
          setPhase(b.winner === solver.toBase58() ? "pass" : "fail");
          return;
        }
        if (b.status === "open" && !b.submission) {
          addLog("verdict: FAIL — submission slot reopened");
          setPhase("fail");
          return;
        }
      }
    })();
    return () => {
      watching.current = false;
    };
  }, [phase, bounty.pda, solver]);

  async function run() {
    setError(null);
    if (!config) {
      setError("Protocol config not found on this cluster — cannot read the enclave key.");
      return;
    }
    if (!canSign) {
      setError("This wallet cannot sign messages, which is required for the intent proof.");
      return;
    }
    if (source.trim().length === 0) {
      setError("Load or paste an exploit first.");
      return;
    }

    setPhase("working");
    setLog([]);
    try {
      const exploit = new TextEncoder().encode(source);
      const exploitSha = sha256Bytes(exploit);
      addLog(`sha256(exploit) = ${bytesToHex(exploitSha)}`);

      addLog("sealing exploit to enclave key…");
      const sealed = await sealTo(exploit, config.enclaveEncPkBytes);
      addLog(`sealed box: ${sealed.length} bytes`);

      addLog("signing submit intent with wallet…");
      const intentMsg = buildSubmitIntentMessage(new PublicKey(bounty.pda), exploit);
      const sig = await signMessage!(intentMsg);

      addLog("uploading to verifier…");
      const { blob_url } = await uploadExploit({
        bounty_pda: bounty.pda,
        claimed_chain_view: {
          env_blob_sha256: bounty.envBlobSha256,
          buyer_enc_pk: bounty.buyerEncPk,
          exploit_sha256: bytesToHex(exploitSha),
          flag_commitment: bounty.flagCommitment,
        },
        solver_pubkey: solver.toBase58(),
        submit_intent_sig: toBase64(sig),
        exploit_sealed_box: toBase64(sealed),
      });
      addLog(`blob url: ${blob_url}`);

      addLog("sending submit_exploit transaction…");
      const signature = await submit(blob_url, exploitSha);
      setTxSig(signature);
      addLog(`tx: ${signature}`);
      addLog("submitted — waiting for the verifier's verdict…");
      setPhase("watching");
      toast.push("Exploit submitted — awaiting verdict.", "success");
    } catch (e) {
      const msg =
        e instanceof Error && e.message.includes("User rejected")
          ? "You rejected the signature or transaction."
          : e instanceof Error
            ? e.message
            : txErrorMessage(e);
      setError(msg);
      addLog(`error: ${msg}`);
      setPhase("compose");
    }
  }

  if (phase === "pass") {
    return (
      <Card style={{ padding: 32, textAlign: "center" }} className="stack">
        <PartyPopper size={44} color="var(--accent-green)" style={{ margin: "0 auto" }} />
        <h2>Flag captured — you won!</h2>
        <p className="dim">
          The verifier confirmed your exploit. The prize and your bond have been paid to your
          wallet, and a Receipt trophy was minted.
        </p>
        <div className="row" style={{ justifyContent: "center" }}>
          <SolAmount lamports={bounty.prizeLamports} />
        </div>
        {txSig && (
          <div className="row" style={{ justifyContent: "center" }}>
            <span className="faint">tx</span> <HashBadge value={txSig} />
          </div>
        )}
        <div className="row" style={{ justifyContent: "center", gap: 10 }}>
          <Link to="/leaderboard">
            <Button variant="primary">See the leaderboard</Button>
          </Link>
          <Link to={`/bounty/${bounty.pda}`}>
            <Button>View bounty</Button>
          </Link>
        </div>
      </Card>
    );
  }

  if (phase === "fail") {
    return (
      <Card style={{ padding: 32, textAlign: "center" }} className="stack">
        <XCircle size={44} color="var(--accent-red)" style={{ margin: "0 auto" }} />
        <h2>Verdict: did not pass</h2>
        <p className="dim">
          The verifier rejected this exploit and the submission slot has reopened. Your bond was
          refunded — refine your approach and try again.
        </p>
        {log.length > 0 && <pre className="rawjson mono" style={{ textAlign: "left" }}>{log.join("\n")}</pre>}
        <div className="row" style={{ justifyContent: "center", gap: 10 }}>
          <Button variant="primary" onClick={() => setPhase("compose")}>
            <Crosshair size={15} /> Try again
          </Button>
          <Link to={`/bounty/${bounty.pda}`}>
            <Button>Back to bounty</Button>
          </Link>
        </div>
      </Card>
    );
  }

  return (
    <div className="stack" style={{ gap: 18 }}>
      <div>
        <h1 style={{ fontSize: 26 }} className="row">
          <Crosshair size={22} color="var(--accent-green)" /> Submit console
        </h1>
        <p className="dim" style={{ margin: "4px 0 0" }}>
          Bounty <Mono>#{bounty.bountyId.toString()}</Mono> · prize{" "}
          <SolAmount lamports={bounty.prizeLamports} />
          {config && (
            <>
              {" "}
              · bond <SolAmount lamports={config.submissionBondLamports} />
            </>
          )}
        </p>
      </div>

      {notOpen && (
        <Card style={{ padding: 14, borderColor: "rgba(255,180,84,.5)" }} className="row">
          <ShieldAlert size={16} color="var(--accent-amber)" />
          <span className="dim">
            This bounty is <Mono>{bounty.status}</Mono> — it isn't accepting submissions right now.
          </span>
        </Card>
      )}

      <Card style={{ padding: 22 }} className="stack">
        <Field
          label="Exploit"
          hint="Drop or paste your exploit. It's sealed to the enclave key locally — the plaintext never leaves your browser unencrypted."
        >
          <FileDrop
            accept=".py,.txt,.sh,text/*"
            label="Drop exploit.py or click to browse"
            loadedName={fileName}
            onFile={(name, contents) => {
              setFileName(name);
              setSource(contents);
            }}
          />
        </Field>
        <Textarea
          value={source}
          placeholder="# or paste your exploit here"
          rows={10}
          onChange={(e) => {
            setSource(e.target.value);
            setFileName(null);
          }}
        />

        {error && (
          <div className="row" style={{ color: "var(--accent-red)" }}>
            <XCircle size={16} /> {error}
          </div>
        )}

        <Button
          variant="primary"
          loading={phase === "working" || phase === "watching"}
          disabled={notOpen}
          onClick={run}
        >
          {phase === "watching" ? "Awaiting verdict…" : "Seal, sign & submit"}
        </Button>
      </Card>

      {log.length > 0 && (
        <Card style={{ padding: 18 }}>
          <div className="row dim" style={{ marginBottom: 8 }}>
            <Terminal size={15} /> activity
          </div>
          <pre className="rawjson mono">{log.join("\n")}</pre>
          {phase === "watching" && (
            <div className="row dim" style={{ marginTop: 8 }}>
              <CheckCircle2 size={14} color="var(--accent-cyan)" /> polling on-chain status…
            </div>
          )}
        </Card>
      )}
    </div>
  );
}
