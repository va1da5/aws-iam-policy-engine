import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/challenge/error")({
  component: RouteComponent,
});

function RouteComponent() {
  return "Something went wrong!";
}
