import React from "react";

import { cn } from "@/lib/utils";

type Props = {
  status: {
    passed: number;
    failed: number;
  };
  children?: React.ReactNode;
};

export default function Status({ status, children }: Props) {
  let success = Math.round(
    (status.passed * 100) / (status.passed + status.failed),
  );

  if (isNaN(success)) success = 0;

  return (
    <div
      className={cn(
        "flex min-h-10 items-center justify-between rounded border border-l-8 border-solid border-gray-300 px-8 py-5",
        status.failed > 0 ? "border-l-red-600" : "border-l-green-600",
      )}
    >
      <div className="flex gap-10">
        <div className="grid justify-items-center">
          <p className="text-3xl">{success}%</p>
          <p className="text-muted-foreground">Success</p>
        </div>

        <div className="grid justify-items-center">
          <p className="text-3xl">{status.passed}</p>
          <p className="text-muted-foreground">Passed</p>
        </div>

        <div className="grid justify-items-center">
          <p className="text-3xl">{status.failed}</p>
          <p className="text-muted-foreground">Failed</p>
        </div>
      </div>

      {success == 100 && <div>{children}</div>}
    </div>
  );
}
