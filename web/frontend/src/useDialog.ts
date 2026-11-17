import { useEffect, useRef, type RefObject } from "react";

/** Keep keyboard focus in a modal and restore it to the invoking control on close. */
export function useDialog(
  ref: RefObject<HTMLElement | null>,
  close: () => void,
  enabled = true,
) {
  const latestClose = useRef(close);
  useEffect(() => {
    latestClose.current = close;
  }, [close]);
  useEffect(() => {
    const panel = ref.current;
    if (!enabled || !panel) return;
    const previous = document.activeElement;
    const controls = () =>
      Array.from(
        panel.querySelectorAll<HTMLElement>(
          'button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
        ),
      ).filter((element) => element.getClientRects().length > 0);
    const first = controls()[0] || panel;
    if (!panel.contains(document.activeElement)) first.focus();
    const key = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        latestClose.current();
      } else if (event.key === "Tab") {
        const items = controls(),
          active = document.activeElement;
        const first = items[0] || panel,
          last = items.at(-1) || panel;
        if (
          !items.length ||
          (event.shiftKey && (active === first || !panel.contains(active)))
        ) {
          event.preventDefault();
          last.focus();
        } else if (
          !event.shiftKey &&
          (active === last || !panel.contains(active))
        ) {
          event.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener("keydown", key);
    return () => {
      document.removeEventListener("keydown", key);
      if (previous instanceof HTMLElement && previous.isConnected)
        previous.focus();
    };
  }, [ref, enabled]);
}
