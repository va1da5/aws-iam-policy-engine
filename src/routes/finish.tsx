import Markdown from "react-markdown";
import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/finish")({
  component: RouteComponent,
});

function RouteComponent() {
  return (
    <div className="prose mx-auto mb-28 mt-20 w-full lg:prose-xl">
      <Markdown>
        {`
## 🎉 Congratulations!

You absolutely crushed it! I hope you had a blast and picked up some valuable insights along the journey. Now, it’s time to roll up those sleeves, put those skills into action, and lock down your cloud like a pro! 🚀

If you’ve got some brilliant ideas for new challenges or any other enhancements, don’t hesitate to jump in! I would love for you to share your thoughts or improvements directly to the [GitHub repository](https://github.com/va1da5/aws-iam-policy-engine) for this project. Let’s make this even better together! 💡✨
`}
      </Markdown>
    </div>
  );
}
