import { ReactNode } from "react";
import * as DialogPrimitive from "@radix-ui/react-dialog";
import { ChevronDown, ChevronUp, X } from "lucide-react";
import { cn } from "@/lib/utils";

interface Props {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  title: ReactNode;
  description?: ReactNode;
  /** Header row above the title (e.g. severity + state chips). */
  meta?: ReactNode;
  /** Right-side actions in the header. */
  actions?: ReactNode;
  /** Show prev/next walkthrough controls. */
  onPrev?: () => void;
  onNext?: () => void;
  hasPrev?: boolean;
  hasNext?: boolean;
  children: ReactNode;
}

export function DetailDrawer({
  open,
  onOpenChange,
  title,
  description,
  meta,
  actions,
  onPrev,
  onNext,
  hasPrev,
  hasNext,
  children,
}: Props) {
  return (
    <DialogPrimitive.Root open={open} onOpenChange={onOpenChange}>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay
          className={cn(
            "fixed inset-0 z-50 bg-black/60 data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0",
          )}
        />
        <DialogPrimitive.Content
          onKeyDown={(e) => {
            if (e.key === "j" && hasNext) {
              e.preventDefault();
              onNext?.();
            } else if (e.key === "k" && hasPrev) {
              e.preventDefault();
              onPrev?.();
            }
          }}
          className={cn(
            "fixed right-0 top-0 z-50 flex h-full w-full max-w-xl flex-col border-l bg-background shadow-xl outline-none",
            "data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:slide-out-to-right data-[state=open]:slide-in-from-right",
          )}
        >
          <div className="flex shrink-0 items-start gap-3 border-b px-6 py-4">
            <div className="min-w-0 flex-1 space-y-1">
              {meta && <div className="flex flex-wrap items-center gap-1.5">{meta}</div>}
              <DialogPrimitive.Title className="truncate text-base font-semibold">
                {title}
              </DialogPrimitive.Title>
              {description && (
                <DialogPrimitive.Description className="truncate text-xs text-muted-foreground">
                  {description}
                </DialogPrimitive.Description>
              )}
            </div>
            <div className="flex items-center gap-1">
              {actions}
              {(onPrev || onNext) && (
                <div className="flex overflow-hidden rounded-md border">
                  <button
                    type="button"
                    aria-label="Previous"
                    disabled={!hasPrev}
                    onClick={onPrev}
                    className="flex h-8 w-8 items-center justify-center hover:bg-accent disabled:opacity-30"
                  >
                    <ChevronUp className="h-4 w-4" />
                  </button>
                  <button
                    type="button"
                    aria-label="Next"
                    disabled={!hasNext}
                    onClick={onNext}
                    className="flex h-8 w-8 items-center justify-center border-l hover:bg-accent disabled:opacity-30"
                  >
                    <ChevronDown className="h-4 w-4" />
                  </button>
                </div>
              )}
              <DialogPrimitive.Close
                aria-label="Close"
                className="flex h-8 w-8 items-center justify-center rounded-md hover:bg-accent"
              >
                <X className="h-4 w-4" />
              </DialogPrimitive.Close>
            </div>
          </div>
          <div className="flex-1 overflow-y-auto px-6 py-4">{children}</div>
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  );
}
