import { ReactNode } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";

interface Props {
  title: string;
  hint?: string;
  className?: string;
  children: ReactNode;
}

export function ChartCard({ title, hint, className, children }: Props) {
  return (
    <Card className={cn("flex flex-col", className)}>
      <CardHeader className="space-y-0 pb-2">
        <CardTitle className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
          {title}
        </CardTitle>
        {hint && <p className="text-[11px] text-muted-foreground/80">{hint}</p>}
      </CardHeader>
      <CardContent className="pt-1">{children}</CardContent>
    </Card>
  );
}
