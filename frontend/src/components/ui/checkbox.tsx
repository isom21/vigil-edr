/**
 * SOC-console checkbox.
 *
 * Sharp-cornered, monospace-aligned, no platform default — matches the
 * tactical aesthetic the rest of the console uses (borders + accents,
 * not rounded toy controls). Keeps the native <input> for a11y +
 * indeterminate semantics; the visual is a sibling <span>.
 */
import * as React from "react";
import { Check, Minus } from "lucide-react";
import { cn } from "@/lib/utils";

export interface CheckboxProps
  extends Omit<React.InputHTMLAttributes<HTMLInputElement>, "type"> {
  indeterminate?: boolean;
}

export const Checkbox = React.forwardRef<HTMLInputElement, CheckboxProps>(
  ({ className, indeterminate, ...props }, ref) => {
    const innerRef = React.useRef<HTMLInputElement>(null);
    React.useImperativeHandle(ref, () => innerRef.current as HTMLInputElement);
    // Native `indeterminate` is a DOM-level property, not an attribute,
    // so we sync it via the ref on every change.
    React.useEffect(() => {
      if (innerRef.current) innerRef.current.indeterminate = !!indeterminate;
    }, [indeterminate]);

    return (
      <span
        className={cn(
          "relative inline-flex h-4 w-4 shrink-0 items-center justify-center",
          className,
        )}
      >
        <input
          ref={innerRef}
          type="checkbox"
          className="peer absolute inset-0 h-full w-full cursor-pointer appearance-none rounded-none border border-border bg-background outline-none transition-colors hover:border-foreground/40 focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1 focus-visible:ring-offset-background checked:border-primary checked:bg-primary indeterminate:border-primary indeterminate:bg-primary"
          {...props}
        />
        {/* Icon overlay — invisible by default, fades in on
            :checked or :indeterminate via peer selectors. */}
        <Check
          aria-hidden="true"
          strokeWidth={3}
          className="pointer-events-none absolute h-3 w-3 text-primary-foreground opacity-0 peer-checked:peer-[:not(:indeterminate)]:opacity-100"
        />
        <Minus
          aria-hidden="true"
          strokeWidth={3}
          className="pointer-events-none absolute h-3 w-3 text-primary-foreground opacity-0 peer-indeterminate:opacity-100"
        />
      </span>
    );
  },
);
Checkbox.displayName = "Checkbox";
