import * as React from "react";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { getActiveChallenge } from "@/utils/tracker";

export const Route = createFileRoute("/challenge/")({
  component: RouteComponent,
});

function RouteComponent() {
  const navigate = useNavigate({ from: "/challenge" });

  const challengeId = getActiveChallenge();

  React.useEffect(() => {
    navigate({
      to: `/challenge/$policyId`,
      replace: true,
      params: {
        policyId: challengeId.toString(),
      },
    });
  }, []);

  return;
}
