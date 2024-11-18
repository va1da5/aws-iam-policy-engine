import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/sandbox")({
  component: RouteComponent,
});

function RouteComponent() {
  return "Hello /sandbox!";
}
