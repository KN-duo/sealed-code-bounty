import { ArrowRight, CheckCircle2, CircleDashed, ShieldHalf } from "lucide-react";

const phases = [
  { done: true, title: "Public website", detail: "This preview is served as static HTTPS content." },
  { done: false, title: "Solana deployment", detail: "The program is not yet deployed to a public cluster." },
  { done: false, title: "AWS Nitro verifier", detail: "TEE execution and attestation are not yet live." },
  { done: false, title: "End-to-end CTF", detail: "Bounty posting and submissions are not enabled." },
];

export function PublicPreview() {
  return (
    <section className="stack" style={{ gap: 28, maxWidth: 820, margin: "48px auto" }}>
      <div className="stack" style={{ gap: 12 }}>
        <div className="row" style={{ color: "var(--accent-green)", gap: 10 }}>
          <ShieldHalf size={20} />
          <span className="mono">SEALED CODE BOUNTY</span>
        </div>
        <h1 style={{ fontSize: 38, lineHeight: 1.15, maxWidth: 680 }}>
          Security challenges with private, verifiable execution.
        </h1>
        <p className="dim" style={{ fontSize: 17, maxWidth: 660 }}>
          A CTF bounty platform in development. This public preview introduces the project;
          it does not accept bounties or run submitted code yet.
        </p>
      </div>

      <div className="card stack" style={{ padding: 24, gap: 18 }}>
        <div>
          <h2 style={{ fontSize: 19 }}>Deployment progress</h2>
          <p className="dim" style={{ marginTop: 4 }}>Live challenge actions stay disabled until the full path is verified.</p>
        </div>
        <div className="stack" style={{ gap: 16 }}>
          {phases.map((phase) => (
            <div className="row" key={phase.title} style={{ alignItems: "flex-start", gap: 12 }}>
              {phase.done ? <CheckCircle2 size={19} color="var(--accent-green)" /> : <CircleDashed size={19} color="var(--text-dim)" />}
              <div>
                <strong>{phase.title}</strong>
                <div className="dim" style={{ marginTop: 3 }}>{phase.detail}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      <p className="dim row" style={{ gap: 8, flexWrap: "wrap" }}>
        <ArrowRight size={16} /> Next: deploy and verify the AWS Nitro staging path on Solana devnet.
      </p>
    </section>
  );
}
