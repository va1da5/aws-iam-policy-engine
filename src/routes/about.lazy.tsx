import Markdown from "@/components/markdown";
import { createLazyFileRoute } from "@tanstack/react-router";

export const Route = createLazyFileRoute("/about")({
  component: RouteComponent,
});

function RouteComponent() {
  return (
    <div className="prose mx-auto mb-28 w-full lg:prose-xl">
      <Markdown className="lg:prose-xl">
        {`
  ## About
  
  This project utilizes a custom-made policy detection engine that closely adheres to the [reference documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies.html) provided by AWS. However, it is important to note that it is not 100% compatible with the original engine and may produce incorrect evaluations in certain instances. Nevertheless, it proves to be sufficiently effective for implementing this educational challenges, allowing participants to gain hands-on experience while learning about AWS IAM policies.

  The engine itself was created as an exercise to gain a deeper understanding of the various options available in AWS IAM policies and how they interact with one another. What better way to explore a subject than by actively implementing a working clone? Once the engine performed well, it would have been a shame to let it languish among the forgotten pet projects. Thus, a new journey began—one focused on gathering intriguing examples that would address different topics in each exercise, building upon one another along the way.

  This project now offers a variety of exercises designed to guide anyone interested in AWS IAM policies. These activities will help users create functional policies while minimizing the risk of making mistakes along the way.

  I encourage anyone interested in the project to come together and enhance it, allowing more people to gain valuable knowledge about AWS IAM policies and how to navigate them effectively. The simplest way to get involved is through the [GitHub repository](https://github.com/va1da5/aws-iam-challenges).
  `}
      </Markdown>
    </div>
  );
}
