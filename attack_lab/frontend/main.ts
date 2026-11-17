import { identity } from "../../web/frontend/src/crypto";
import { wrap, saveBackup } from "../../web/frontend/src/keystore";
import "./style.css";
const actions = [
  ["tamper_next", "Tamper ciphertext"],
  ["replay_last", "Replay old envelope"],
  ["drop_next", "Drop next message"],
  ["reorder_next", "Reorder next messages"],
  ["inject_next", "Inject forged message"],
  ["mitm_next_handshake", "MITM key substitution"],
  ["brute_force", "Login brute-force / lockout"],
];
const status = document.querySelector<HTMLParagraphElement>("#status")!;
const button = (id: string) =>
  document.querySelector<HTMLButtonElement>("#" + id)!;
let config:
  { generation: string; accounts: string[]; password: string } | undefined;
let started = false,
  sequence = 0;
async function api(path: string, body?: unknown) {
  const response = await fetch("/lab/" + path, {
    method: body === undefined ? "GET" : "POST",
    headers: body === undefined ? {} : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await response.json();
  if (!response.ok) throw Error(data.detail || "Lab request failed");
  return data;
}
function show(error: unknown) {
  status.textContent = error instanceof Error ? error.message : String(error);
}
const frames = [
  document.querySelector<HTMLIFrameElement>("#alice")!,
  document.querySelector<HTMLIFrameElement>("#bob")!,
];
function input(frame: HTMLIFrameElement, label: string, value: string) {
  const doc = frame.contentDocument!;
  const field = Array.from(
    doc.querySelectorAll<HTMLInputElement>("input"),
  ).find(
    (e) =>
      e.getAttribute("aria-label") === label ||
      e.parentElement?.textContent?.trim().startsWith(label),
  );
  if (!field) throw Error("Victim form not ready");
  const view = frame.contentWindow!;
  Object.getOwnPropertyDescriptor(
    (view as any).HTMLInputElement.prototype,
    "value",
  )!.set!.call(field, value);
  field.dispatchEvent(new (view as any).Event("input", { bubbles: true }));
  field.dispatchEvent(new (view as any).Event("change", { bubbles: true }));
}
function click(frame: HTMLIFrameElement, text: string) {
  const el = Array.from(frame.contentDocument!.querySelectorAll("button")).find(
    (e) => e.textContent?.includes(text),
  );
  if (!el) throw Error("Victim control not ready: " + text);
  el.click();
}
async function ready(frame: HTMLIFrameElement) {
  const end = Date.now() + 10000;
  while (Date.now() < end) {
    if (frame.contentDocument?.querySelector("input")) return;
    await new Promise((r) => setTimeout(r, 30));
  }
  throw Error("Victim bundle did not load");
}
async function loadFrame(frame: HTMLIFrameElement, path: string) {
  await new Promise<void>((resolve) => {
    frame.addEventListener("load", () => resolve(), { once: true });
    frame.src = path;
  });
  await ready(frame);
}
async function prepareIdentity(name: string) {
  if (!config) throw Error("Start a session first");
  const generated = await identity();
  try {
    await saveBackup(
      await wrap(
        name,
        config.password,
        generated.publicPem,
        generated.privateBytes,
      ),
    );
    await api("identity", {
      generation: config.generation,
      username: name,
      public_key: generated.publicPem,
    });
  } finally {
    generated.privateBytes.fill(0);
  }
}
async function bootstrap() {
  if (!config) throw Error("Start a session first");
  button("connect").disabled = true;
  try {
    status.textContent =
      "Generating private identities locally with the production crypto and keystore modules…";
    for (const name of config.accounts) await prepareIdentity(name);
    for (let i = 0; i < frames.length; i++) {
      await ready(frames[i]);
      input(frames[i], "Username", config.accounts[i]);
      input(frames[i], "Password", config.password);
      input(frames[i], "Peer username", config.accounts[1 - i]);
      click(frames[i], "Log in");
      await new Promise((r) => setTimeout(r, 250));
    }
    button("send").disabled = false;
    button("follow").disabled = false;
    status.textContent =
      "Victims connected using the unchanged production bundle. Their checks decide the outcome.";
  } catch (e) {
    show(e);
    button("connect").disabled = false;
  }
}
button("start").onclick = async () => {
  try {
    config = await api("session", {});
    started = true;
    button("connect").disabled = false;
    button("reset").disabled = false;
    document
      .querySelectorAll<HTMLButtonElement>("#actions button")
      .forEach((b) => (b.disabled = false));
    status.textContent =
      "Lab session ready. Sandbox accounts: lab_alice / lab_bob. Connect victims, or arm MITM first.";
  } catch (e) {
    show(e);
  }
};
button("connect").onclick = () => void bootstrap();
button("reset").onclick = async () => {
  try {
    config = await api("reset", {});
    sequence = 0;
    await Promise.all(
      frames.map((frame) =>
        loadFrame(frame, "/victim?reset=" + config!.generation),
      ),
    );
    button("connect").disabled = false;
    button("send").disabled = true;
    button("follow").disabled = true;
    document.querySelector("#detections")!.replaceChildren();
    status.textContent =
      "Lab DB wiped and demo accounts reseeded. Connect victims again.";
  } catch (e) {
    show(e);
  }
};
for (const id of ["send", "follow"])
  button(id).onclick = () => {
    try {
      input(frames[0], "Message", "Sandbox message " + ++sequence);
      click(frames[0], "Send");
    } catch (e) {
      show(e);
    }
  };
for (const [action, title] of actions) {
  const b = document.createElement("button");
  b.textContent = title;
  b.disabled = true;
  b.dataset.action = action;
  b.onclick = async () => {
    try {
      if (action === "brute_force") {
        await prepareIdentity("lab_lockout");
        const result = await api("brute-force", {});
        await loadFrame(frames[0], "/victim?lockout=" + Date.now());
        input(frames[0], "Username", "lab_lockout");
        input(frames[0], "Password", config!.password);
        input(frames[0], "Peer username", "lab_bob");
        click(frames[0], "Log in");
        status.textContent = result.locked
          ? "Sandbox account locked by the real login guard. Final attempt rejected before PBKDF2."
          : "No lockout detected";
      } else {
        await api("arm", { action, target: "lab_alice" });
        status.textContent =
          "Armed " + title + ". Waiting for a real victim report.";
      }
    } catch (e) {
      show(e);
    }
  };
  document.querySelector("#actions")!.append(b);
}
async function poll() {
  if (started)
    try {
      const state = await api("state");
      document.querySelector("#wire")!.textContent = state.wire
        .map((e: unknown) => JSON.stringify(e, null, 2))
        .join("\n\n");
      document.querySelector("#attempts")!.textContent = state.events
        .filter((e: any) => e.event.startsWith("lab_"))
        .map((e: unknown) => JSON.stringify(e))
        .join("\n");
      const feed = document.querySelector("#detections")!;
      feed.replaceChildren();
      for (const e of state.events) {
        if (
          !["security_alert", "account_locked", "lockout_rejected"].includes(
            e.event,
          )
        )
          continue;
        const row = document.createElement("p");
        row.className = "detection";
        row.textContent =
          e.event === "security_alert"
            ? `${e.reported_by}: ${e.alert} — ${e.reason}`
            : `${e.username}: ${e.event} — real lockout guard`;
        feed.append(row);
      }
    } catch (e) {
      show(e);
    }
  setTimeout(poll, 1000);
}
// The static HTML may appear before this module loads on a cold connection.
// Enable the first control only after its handlers have been installed.
button("start").disabled = false;
void poll();
