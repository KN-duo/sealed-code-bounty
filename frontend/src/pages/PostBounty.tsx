import { useMemo, useState } from "react";
import type { ReactNode } from "react";
import { useWallet } from "@solana/wallet-adapter-react";
import { WalletMultiButton } from "@solana/wallet-adapter-react-ui";
import * as anchor from "@anchor-lang/core";
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Download,
  KeyRound,
  ShieldAlert,
} from "lucide-react";
import { Card, Mono } from "../components/ui/atoms";
import { Button } from "../components/ui/Button";
import { Field, Input } from "../components/ui/forms";
import { HashBadge } from "../components/ui/HashBadge";
import { RestoreKey } from "../components/buyer/RestoreKey";
import { Link } from "../router";
import { useBuyerKey } from "../hooks/useBuyerKey";
import { useProgram } from "../hooks/useProgram";
import { useConfig } from "../hooks/useData";
import { downloadBackup } from "../lib/backup";
import { bytesToHex, hexToBytes, solToLamports } from "../lib/format";
import { buildManifest, downloadManifest, manifestSha256Hex, validateForm } from "../lib/manifest";
import type { ManifestForm, TargetKind } from "../lib/manifest";
import { bountyPda } from "../lib/pda";
import { sealBounty } from "../lib/runner";
import { createBounty, txErrorMessage } from "../lib/tx";
import { useToast } from "../hooks/useToast";

type Step = "key" | "manifest" | "review" | "done";

function randomBountyId(): anchor.BN {
  const buf = new Uint8Array(8);
  crypto.getRandomValues(buf);
  // keep it comfortably < 2^53 range concerns by masking the top byte
  buf[7] = 0;
  return new anchor.BN(buf, "le");
}

const DEFAULT_FORM: ManifestForm = {
  imageUrl: "",
  imageSha256: "",
  kind: "tcp_service",
  entrypoint: "./run.sh",
  memoryMb: 512,
  timeoutS: 60,
  deterministic: true,
  seed: 0,
  flagPlaceholder: "FLAG{...}",
};

export function PostBounty() {
  const wallet = useWallet();
  const program = useProgram();
  const toast = useToast();
  const { keypair, generate, restore } = useBuyerKey();
  const config = useConfig();

  const [step, setStep] = useState<Step>("key");
  const [freshlyGenerated, setFreshlyGenerated] = useState(false);
  const [backedUp, setBackedUp] = useState(false);

  const [form, setForm] = useState<ManifestForm>(DEFAULT_FORM);
  const [prizeSol, setPrizeSol] = useState("0.5");
  const [deadlineLocal, setDeadlineLocal] = useState(() => {
    const d = new Date(Date.now() + 7 * 86400_000);
    d.setSeconds(0, 0);
    return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
  });

  const [bountyId] = useState(randomBountyId);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [txSig, setTxSig] = useState<string | null>(null);

  const keyReady = keypair && (backedUp || !freshlyGenerated);
  const configMissing = config.state.kind === "empty" || config.state.kind === "success" && config.state.data === null;

  const bountyAddress = useMemo(
    () => (wallet.publicKey ? bountyPda(wallet.publicKey, bountyId).toBase58() : null),
    [wallet.publicKey, bountyId],
  );

  // -- wallet gate ---------------------------------------------------------
  if (!wallet.publicKey) {
    return (
      <Card style={{ padding: 40, textAlign: "center" }} className="stack">
        <ShieldAlert size={34} className="dim" style={{ margin: "0 auto" }} />
        <h2>Connect a wallet to post a bounty</h2>
        <p className="dim">You'll fund the prize escrow and sign the create transaction.</p>
        <div style={{ margin: "0 auto" }}>
          <WalletMultiButton />
        </div>
      </Card>
    );
  }

  async function onGenerate() {
    await generate();
    setFreshlyGenerated(true);
    setBackedUp(false);
  }

  function onDownloadBackup() {
    if (!keypair) return;
    downloadBackup(keypair);
    setBackedUp(true);
    toast.push("Backup downloaded — store it safely.", "success");
  }

  async function onPost() {
    if (!program || !wallet.publicKey || !keypair || !bountyAddress) return;
    setError(null);
    setBusy(true);
    try {
      const manifest = buildManifest(form);
      const manifestSha = hexToBytes(manifestSha256Hex(manifest));
      const envBlobSha = hexToBytes(form.imageSha256.trim());

      // 1) enclave seals the environment and returns the flag commitment.
      const sealed = await sealBounty(bountyAddress);
      const flagCommitment = hexToBytes(sealed.flag_commitment);

      // 2) fund escrow + pin commitments on-chain.
      const deadlineUnix = Math.floor(new Date(deadlineLocal).getTime() / 1000);
      const sig = await createBounty(program, wallet.publicKey, {
        bountyId,
        prizeLamports: solToLamports(Number(prizeSol)),
        deadline: new anchor.BN(deadlineUnix),
        manifestSha256: manifestSha,
        envBlobSha256: envBlobSha,
        flagCommitment,
        buyerEncPk: keypair.publicKey,
      });
      setTxSig(sig);
      setStep("done");
      toast.push("Bounty posted!", "success");
    } catch (e) {
      setError(txErrorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  const formErrors = validateForm(form);
  const prizeValid = Number(prizeSol) > 0;
  const deadlineValid = new Date(deadlineLocal).getTime() > Date.now();

  return (
    <div className="stack" style={{ gap: 20, maxWidth: 720, margin: "0 auto" }}>
      <div>
        <h1 style={{ fontSize: 26 }}>Post a bounty</h1>
        <p className="dim" style={{ margin: "4px 0 0" }}>
          Fund a prize, pin your target, and let hunters try to break it.
        </p>
      </div>

      <Stepper step={step} />

      {configMissing && (
        <Card style={{ padding: 14, borderColor: "rgba(255,180,84,.5)" }} className="row">
          <AlertTriangle size={18} color="var(--accent-amber)" />
          <span className="dim">
            Protocol config not found on this cluster — <Mono>create_bounty</Mono> will fail until an
            operator initializes it.
          </span>
        </Card>
      )}

      {/* STEP: KEY ------------------------------------------------------- */}
      {step === "key" && (
        <Card style={{ padding: 24 }} className="stack">
          <h3 className="row">
            <KeyRound size={18} color="var(--accent-green)" /> Your decryption key
          </h3>
          <p className="dim" style={{ marginTop: 0 }}>
            A winning exploit is encrypted to <em>your</em> key. It lives only in this browser
            session — if you lose it, you can never open the reveal. Back it up now.
          </p>

          {!keypair && (
            <>
              <Button variant="primary" onClick={onGenerate}>
                Generate decryption key
              </Button>
              <div className="divider">or</div>
              <RestoreKey
                onRestore={async (json) => {
                  const kp = await restore(json);
                  setBackedUp(true);
                  setFreshlyGenerated(false);
                  return kp;
                }}
              />
            </>
          )}

          {keypair && (
            <div className="stack" style={{ gap: 14 }}>
              <div className="fact">
                <div className="fact-label">Public key (goes on-chain)</div>
                <HashBadge value={bytesToHex(keypair.publicKey)} />
              </div>

              {freshlyGenerated && !backedUp && (
                <Card style={{ padding: 14, borderColor: "rgba(255,95,110,.5)" }} className="stack">
                  <div className="row" style={{ color: "var(--accent-red)" }}>
                    <AlertTriangle size={16} /> Secret shown once — download the backup to continue.
                  </div>
                  <pre className="rawjson mono" style={{ margin: 0 }}>
                    {bytesToHex(keypair.secretKey)}
                  </pre>
                </Card>
              )}

              <div className="row" style={{ gap: 10, flexWrap: "wrap" }}>
                <Button variant={backedUp ? "default" : "primary"} onClick={onDownloadBackup}>
                  <Download size={15} /> Download backup
                </Button>
                <Button
                  variant="primary"
                  disabled={!keyReady}
                  onClick={() => setStep("manifest")}
                >
                  Continue <ArrowRight size={15} />
                </Button>
              </div>
              {backedUp && (
                <div className="row" style={{ color: "var(--accent-green)" }}>
                  <CheckCircle2 size={15} /> Backed up
                </div>
              )}
            </div>
          )}
        </Card>
      )}

      {/* STEP: MANIFEST -------------------------------------------------- */}
      {step === "manifest" && (
        <Card style={{ padding: 24 }} className="stack">
          <h3>Target manifest</h3>
          <p className="dim" style={{ marginTop: 0 }}>
            The environment the verifier boots and the rules it runs under (schema v2).
          </p>

          <Field label="Image tarball URL" hint="https:// link to the environment tarball.">
            <Input
              value={form.imageUrl}
              placeholder="https://storage.example.com/target.tar.gz"
              onChange={(e) => setForm({ ...form, imageUrl: e.target.value })}
            />
          </Field>
          <Field label="Image tarball sha256" hint="64 hex chars — pins the exact environment.">
            <Input
              value={form.imageSha256}
              placeholder="e3b0c44298fc1c14…"
              onChange={(e) => setForm({ ...form, imageSha256: e.target.value })}
            />
          </Field>

          <div className="two-col">
            <Field label="Target kind">
              <select
                className="input"
                value={form.kind}
                onChange={(e) => setForm({ ...form, kind: e.target.value as TargetKind })}
              >
                <option value="tcp_service">tcp_service</option>
                <option value="binary">binary</option>
              </select>
            </Field>
            <Field label="Entrypoint">
              <Input
                value={form.entrypoint}
                onChange={(e) => setForm({ ...form, entrypoint: e.target.value })}
              />
            </Field>
          </div>

          <div className="two-col">
            <Field label="Memory (MB)">
              <Input
                type="number"
                value={form.memoryMb}
                onChange={(e) => setForm({ ...form, memoryMb: Number(e.target.value) })}
              />
            </Field>
            <Field label="Timeout (s)">
              <Input
                type="number"
                value={form.timeoutS}
                onChange={(e) => setForm({ ...form, timeoutS: Number(e.target.value) })}
              />
            </Field>
          </div>

          <Field label="Flag placeholder" hint="The token replaced by the real secret flag at seal time.">
            <Input
              value={form.flagPlaceholder}
              onChange={(e) => setForm({ ...form, flagPlaceholder: e.target.value })}
            />
          </Field>

          <div className="two-col">
            <Field label="Prize (SOL)">
              <Input
                type="number"
                step="0.01"
                value={prizeSol}
                onChange={(e) => setPrizeSol(e.target.value)}
              />
            </Field>
            <Field label="Deadline">
              <Input
                type="datetime-local"
                value={deadlineLocal}
                onChange={(e) => setDeadlineLocal(e.target.value)}
              />
            </Field>
          </div>

          {formErrors.length > 0 && (
            <ul className="errlist">
              {formErrors.map((e) => (
                <li key={e}>{e}</li>
              ))}
            </ul>
          )}

          <div className="row" style={{ gap: 10 }}>
            <Button variant="ghost" onClick={() => setStep("key")}>
              Back
            </Button>
            <Button
              variant="primary"
              disabled={formErrors.length > 0 || !prizeValid || !deadlineValid}
              onClick={() => setStep("review")}
            >
              Review <ArrowRight size={15} />
            </Button>
          </div>
        </Card>
      )}

      {/* STEP: REVIEW ---------------------------------------------------- */}
      {step === "review" && (
        <Card style={{ padding: 24 }} className="stack">
          <h3>Review &amp; post</h3>
          <div className="stack" style={{ gap: 12 }}>
            <ReviewRow label="Prize">
              <Mono>{prizeSol} SOL</Mono>
            </ReviewRow>
            <ReviewRow label="Deadline">
              <Mono>{new Date(deadlineLocal).toLocaleString()}</Mono>
            </ReviewRow>
            <ReviewRow label="Bounty address">
              {bountyAddress && <HashBadge value={bountyAddress} />}
            </ReviewRow>
            <ReviewRow label="Manifest sha256">
              <HashBadge value={manifestSha256Hex(buildManifest(form))} />
            </ReviewRow>
            <ReviewRow label="Environment sha256">
              <HashBadge value={form.imageSha256.trim().toLowerCase()} />
            </ReviewRow>
            <ReviewRow label="Reveal key">
              {keypair && <HashBadge value={bytesToHex(keypair.publicKey)} />}
            </ReviewRow>
          </div>

          <div className="row" style={{ gap: 10 }}>
            <Button variant="ghost" onClick={() => downloadManifest(buildManifest(form))}>
              <Download size={15} /> manifest.json
            </Button>
          </div>

          <p className="dim" style={{ fontSize: 13 }}>
            Posting will ask the verifier to seal the environment, then send{" "}
            <Mono>create_bounty</Mono> — this funds the prize escrow from your wallet.
          </p>

          {error && (
            <Card style={{ padding: 12, borderColor: "rgba(255,95,110,.5)" }} className="row">
              <AlertTriangle size={16} color="var(--accent-red)" />
              <span>{error}</span>
            </Card>
          )}

          <div className="row" style={{ gap: 10 }}>
            <Button variant="ghost" onClick={() => setStep("manifest")} disabled={busy}>
              Back
            </Button>
            <Button variant="primary" loading={busy} onClick={onPost}>
              Seal &amp; post bounty
            </Button>
          </div>
        </Card>
      )}

      {/* STEP: DONE ------------------------------------------------------ */}
      {step === "done" && (
        <Card style={{ padding: 32, textAlign: "center" }} className="stack">
          <CheckCircle2 size={40} color="var(--accent-green)" style={{ margin: "0 auto" }} />
          <h2>Bounty is live</h2>
          <p className="dim">Hunters can now try to break your target.</p>
          {txSig && (
            <div className="row" style={{ justifyContent: "center" }}>
              <span className="faint">tx</span> <HashBadge value={txSig} />
            </div>
          )}
          <div className="row" style={{ justifyContent: "center", gap: 10 }}>
            {bountyAddress && (
              <Link to={`/bounty/${bountyAddress}`}>
                <Button variant="primary">View bounty</Button>
              </Link>
            )}
            <Link to="/manage">
              <Button>Manage my bounties</Button>
            </Link>
          </div>
        </Card>
      )}
    </div>
  );
}

function Stepper({ step }: { step: Step }) {
  const steps: { key: Step; label: string }[] = [
    { key: "key", label: "Key" },
    { key: "manifest", label: "Manifest" },
    { key: "review", label: "Review" },
    { key: "done", label: "Done" },
  ];
  const idx = steps.findIndex((s) => s.key === step);
  return (
    <div className="stepper">
      {steps.map((s, i) => (
        <div key={s.key} className={`stepper-item ${i <= idx ? "stepper-done" : ""}`.trim()}>
          <span className="stepper-dot">{i + 1}</span>
          {s.label}
        </div>
      ))}
    </div>
  );
}

function ReviewRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="spread">
      <span className="dim">{label}</span>
      {children}
    </div>
  );
}
