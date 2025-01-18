import NavBar from "@/components/navbar";
import { createRootRoute, Outlet } from "@tanstack/react-router";
// import { TanStackRouterDevtools } from "@tanstack/router-devtools";

export const Route = createRootRoute({
  component: () => (
    <>
      <div className="container mx-auto w-full">
        <NavBar />

        <div className="mb-10"></div>

        <Outlet />
        <div className="mb-48"></div>
      </div>
      {/* <TanStackRouterDevtools /> */}
    </>
  ),
});
