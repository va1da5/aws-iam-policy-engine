import { createLazyFileRoute } from '@tanstack/react-router'

export const Route = createLazyFileRoute('/sandbox')({
  component: RouteComponent,
})

function RouteComponent() {
  return 'Under construction..'
}
