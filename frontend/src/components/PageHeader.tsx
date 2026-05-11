import { ReactNode } from "react";

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="flex items-end justify-between border-b px-8 py-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-pretty">{title}</h1>
        {description &&
          (typeof description === "string" ? (
            <p className="mt-1 text-sm text-muted-foreground">{description}</p>
          ) : (
            <div className="mt-1 text-sm">{description}</div>
          ))}
      </div>
      {actions && <div className="flex gap-2">{actions}</div>}
    </div>
  );
}
