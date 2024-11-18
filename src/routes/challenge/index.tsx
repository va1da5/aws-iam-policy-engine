import * as React from "react";
import { createFileRoute, useNavigate } from "@tanstack/react-router";

export const Route = createFileRoute("/challenge/")({
  component: RouteComponent,
});

function RouteComponent() {
  const navigate = useNavigate({ from: "/challenge" });

  const challengeId = 1;

  React.useEffect(() => {
    navigate({
      to: `/challenge/$policyId`,
      replace: true,
      params: {
        policyId: String(challengeId),
      },
    });
  }, []);

  return;
}
