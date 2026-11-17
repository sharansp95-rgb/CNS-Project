// Presigned-URL transfers. File bytes go browser <-> object storage directly;
// this app's server only authorises URLs and records ciphertext metadata.
import { AttachmentError } from "./fileCrypto";

export interface Presigned {
  method: string;
  url: string;
  headers: Record<string, string>;
}
export async function api<T>(
  token: string,
  method: string,
  path: string,
  body?: unknown,
): Promise<T> {
  const r = await fetch(path, {
    method,
    headers: {
      Authorization: "Bearer " + token,
      ...(body ? { "Content-Type": "application/json" } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!r.ok) {
    let detail = "";
    try {
      detail = (await r.json()).detail;
    } catch {
      /* non-JSON error */
    }
    throw new Error(detail || `Request failed (${r.status})`);
  }
  return r.json();
}
function xhr(
  method: string,
  url: string,
  headers: Record<string, string>,
  body: Uint8Array | null,
  responseType: XMLHttpRequestResponseType,
  onProgress: ((loaded: number, total: number) => void) | undefined,
  signal: AbortSignal | undefined,
  upload: boolean,
): Promise<XMLHttpRequest> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new DOMException("Cancelled", "AbortError"));
    const x = new XMLHttpRequest();
    x.open(method, url);
    x.responseType = responseType;
    for (const [k, v] of Object.entries(headers)) x.setRequestHeader(k, v);
    const target = upload ? x.upload : x;
    target.onprogress = (e) => onProgress?.(e.loaded, e.lengthComputable ? e.total : 0);
    x.onload = () => (x.status >= 200 && x.status < 300 ? resolve(x) : reject(new Error(`Storage returned ${x.status}`)));
    x.onerror = () => reject(new Error("Network error talking to storage"));
    x.onabort = () => reject(new DOMException("Cancelled", "AbortError"));
    signal?.addEventListener("abort", () => x.abort(), { once: true });
    x.send(body as XMLHttpRequestBodyInit | null);
  });
}
export const putObject = (
  p: Presigned,
  data: Uint8Array,
  onProgress?: (loaded: number, total: number) => void,
  signal?: AbortSignal,
) => xhr(p.method, p.url, p.headers, data, "text", onProgress, signal, true);
export async function getObject(
  url: string,
  onProgress?: (loaded: number, total: number) => void,
  signal?: AbortSignal,
): Promise<Uint8Array> {
  try {
    const x = await xhr("GET", url, {}, null, "arraybuffer", onProgress, signal, false);
    return new Uint8Array(x.response as ArrayBuffer);
  } catch (e) {
    if ((e as Error).name === "AbortError") throw e;
    throw new AttachmentError("download", "Could not download the attachment: " + (e as Error).message);
  }
}
