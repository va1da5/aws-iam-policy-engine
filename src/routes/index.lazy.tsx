import { createLazyFileRoute, useNavigate } from "@tanstack/react-router";
import Markdown from "react-markdown";
import { Button } from "@/components/ui/button";

export const Route = createLazyFileRoute("/")({
  component: Index,
});

function Index() {
  const navigate = useNavigate({ from: "/" });

  return (
    <div className="prose lg:prose-xl mx-auto mb-28 w-full">
      <Markdown>
        {`
# Welcome!

AWS IAM is a fundamental pillar of the public cloud security. It acts as the de facto perimeter between your application and the vast expanse of the public internet. Misconfigurations within IAM can lead to access vulnerabilities, giving malicious actors opportunities to exploit them. The consequences of such oversights can be severe, so it’s advisable to invest time in learning IAM concepts to mitigate associated risks. Understanding the intricacies of IAM policies is paramount; it empowers you to craft them more effectively and ensures that no over-permissive access is granted.


These challenges will assist you in familiarizing yourself with AWS IAM policies and present you with important concepts that will enhance your understanding when crafting your own policies.
`}
      </Markdown>

      <div className="flex w-full justify-center">
        <Button
          size="xl"
          onClick={() =>
            navigate({
              to: "/challenge/$policyId",
              params: {
                policyId: "1",
              },
            })
          }
        >
          Start Challenge!
        </Button>
      </div>
    </div>
  );
}
