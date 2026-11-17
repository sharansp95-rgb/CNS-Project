// Small preview shown in the chat before the full file is downloaded. It is
// redrawn through a canvas, so it never carries metadata, and travels only
// inside the encrypted chat message.
import { MAX_THUMB } from "./descriptor";

const SIZE = 160;
async function frame(blobUrl: string, kind: "image" | "video"): Promise<CanvasImageSource & { w: number; h: number }> {
  if (kind === "image") {
    const img = new Image();
    img.decoding = "async";
    img.src = blobUrl;
    await img.decode();
    return Object.assign(img, { w: img.naturalWidth, h: img.naturalHeight });
  }
  const v = document.createElement("video");
  v.muted = true;
  v.preload = "auto";
  v.src = blobUrl;
  await new Promise<void>((res, rej) => {
    v.onloadeddata = () => res();
    v.onerror = () => rej(new Error("video decode failed"));
    setTimeout(() => rej(new Error("video thumbnail timeout")), 8000);
  });
  v.currentTime = Math.min(0.1, (v.duration || 1) / 2);
  await new Promise<void>((res) => {
    v.onseeked = () => res();
    setTimeout(res, 2000);
  });
  return Object.assign(v, { w: v.videoWidth, h: v.videoHeight });
}
export async function makeThumbnail(
  bytes: Uint8Array,
  mime: string,
  kind: "image" | "video",
): Promise<Uint8Array | undefined> {
  const url = URL.createObjectURL(new Blob([bytes as BlobPart], { type: mime }));
  try {
    const src = await frame(url, kind);
    if (!src.w || !src.h) return undefined;
    for (const [side, quality] of [[SIZE, 0.6], [SIZE, 0.4], [112, 0.4], [80, 0.35]] as const) {
      const scale = Math.min(1, side / Math.max(src.w, src.h));
      const canvas = document.createElement("canvas");
      canvas.width = Math.max(1, Math.round(src.w * scale));
      canvas.height = Math.max(1, Math.round(src.h * scale));
      canvas.getContext("2d")!.drawImage(src, 0, 0, canvas.width, canvas.height);
      const blob = await new Promise<Blob | null>((r) => canvas.toBlob(r, "image/jpeg", quality));
      if (blob && blob.size <= MAX_THUMB) return new Uint8Array(await blob.arrayBuffer());
    }
  } catch {
    /* A missing preview never blocks sending. */
  } finally {
    URL.revokeObjectURL(url);
  }
  return undefined;
}
