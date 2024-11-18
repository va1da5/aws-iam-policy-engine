import NavBar from "@/components/navbar";
import { createRootRoute, Outlet } from "@tanstack/react-router";
import { TanStackRouterDevtools } from "@tanstack/router-devtools";

export const Route = createRootRoute({
  component: () => (
    <>
      <div className="container m-4 mx-auto w-full">
        <NavBar />

        <div className="mb-10"></div>

        <Outlet />
      </div>
      <TanStackRouterDevtools />
    </>
  ),
});
