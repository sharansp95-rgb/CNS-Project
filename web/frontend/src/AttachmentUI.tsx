import React, { useEffect, useRef, useState } from "react";
import type { Session, Progress, OpenedAttachment } from "./session";
import { parseDescriptor, type Descriptor } from "./attachments/descriptor";

const mb = (n: number) =>
  n >= 1048576 ? (n / 1048576).toFixed(1) + " MB" : Math.ceil(n / 1024) + " KB";
export const stageText = (p: Progress) =>
  `${p.stage}… ${Math.round(p.fraction * 100)}%`;

export function Lightbox({ item, close }: { item: OpenedAttachment; close: () => void }) {
  useEffect(() => {
    const key = (e: KeyboardEvent) => e.key === "Escape" && close();
    addEventListener("keydown", key);
    return () => removeEventListener("keydown", key);
  }, [close]);
  return (
    <div className="modal-backdrop lightbox" onClick={close}>
      <section role="dialog" aria-modal="true" aria-label="Image viewer" onClick={(e) => e.stopPropagation()}>
        <button className="close" onClick={close} autoFocus aria-label="Close image viewer">×</button>
        <img src={item.url} alt={item.name} />
        <p className="muted small">{item.name} · {mb(item.size)}</p>
      </section>
    </div>
  );
}

export function AttachmentCard({
  session,
  descriptor: d,
  mine,
  onReceipt,
  onZoom,
}: {
  session: Session;
  descriptor: Descriptor;
  mine: boolean;
  onReceipt: () => void;
  onZoom: (a: OpenedAttachment) => void;
}) {
  const [progress, setProgress] = useState<Progress>();
  const [error, setError] = useState("");
  const abort = useRef<AbortController>(undefined);
  const opened = session.opened.get(d.id);
  async function open() {
    setError("");
    abort.current = new AbortController();
    try {
      const a = await session.openAttachment(d, setProgress, abort.current.signal);
      setProgress(undefined);
      if (d.kind === "image") onZoom(a);
    } catch (e) {
      setProgress(undefined);
      if ((e as Error).name !== "AbortError") setError((e as Error).message);
    }
  }
  function save(a: OpenedAttachment) {
    const link = document.createElement("a");
    link.href = a.url;
    link.download = a.name; // sanitized, extension from the verified content type
    link.click();
  }
  const thumb = d.thumb ? "data:image/jpeg;base64," + d.thumb : undefined;
  return (
    <div className={"bubble attachment " + (mine ? "sent" : "received")} data-testid="attachment">
      {opened && d.kind === "video" ? (
        <video src={opened.url} controls playsInline preload="metadata" aria-label={"Video " + d.name} />
      ) : opened ? (
        <img className="att-full" src={opened.url} alt={d.name} onClick={() => onZoom(opened)} />
      ) : thumb ? (
        <button className="att-thumb" onClick={() => void open()} aria-label={`Open ${d.kind} ${d.name}`}>
          <img src={thumb} alt="" />
          <span className="att-badge">{d.kind === "video" ? "▶ Play" : "Open"}</span>
        </button>
      ) : (
        <button className="att-thumb att-nothumb" onClick={() => void open()} aria-label={`Open ${d.kind} ${d.name}`}>
          {d.kind === "video" ? "▶" : "🖼"}
        </button>
      )}
      <div className="att-meta">
        <strong>{d.name}</strong>
        <span>{mb(d.size)} · {d.kind}</span>
      </div>
      {progress && (
        <div className="att-progress">
          <div role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(progress.fraction * 100)}>
            <span style={{ width: `${progress.fraction * 100}%` }} />
          </div>
          <small>{stageText(progress)}</small>
          <button onClick={() => abort.current?.abort()}>Cancel</button>
        </div>
      )}
      {error && <p role="alert" className="att-error">⚠ {error}</p>}
      <div className="att-actions">
        {opened && <button onClick={() => save(opened)}>Save</button>}
        <button onClick={onReceipt} aria-label={"Security receipt: attachment " + d.name}>
          Receipt ✓✓
        </button>
      </div>
    </div>
  );
}

export const asDescriptor = (message: string) => parseDescriptor(message);
