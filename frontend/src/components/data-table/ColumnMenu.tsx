import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { Columns3, Check } from "lucide-react";
import { Button } from "@/components/ui/button";
import type { ColumnDef } from "./types";

interface Props<T> {
  columns: ColumnDef<T>[];
  hidden: string[];
  onChange: (hidden: string[]) => void;
}

export function ColumnMenu<T>({ columns, hidden, onChange }: Props<T>) {
  const toggle = (id: string) => {
    if (hidden.includes(id)) onChange(hidden.filter((h) => h !== id));
    else onChange([...hidden, id]);
  };

  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <Button variant="outline" size="sm" className="gap-2">
          <Columns3 className="h-4 w-4" />
          Columns
        </Button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content
          align="end"
          sideOffset={6}
          className="z-50 min-w-[14rem] rounded-md border bg-background p-1 text-foreground shadow-md"
        >
          <div className="px-2 py-1.5 text-xs font-medium text-muted-foreground">
            Visible columns
          </div>
          {columns.map((c) => {
            const visible = !hidden.includes(c.id);
            return (
              <DropdownMenu.Item
                key={c.id}
                onSelect={(e) => {
                  e.preventDefault();
                  toggle(c.id);
                }}
                className="flex cursor-pointer items-center gap-2 rounded-sm px-2 py-1.5 text-sm outline-none focus:bg-accent"
              >
                <span className="flex h-4 w-4 items-center justify-center">
                  {visible ? <Check className="h-3.5 w-3.5" /> : null}
                </span>
                {c.header ?? c.id}
              </DropdownMenu.Item>
            );
          })}
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}
