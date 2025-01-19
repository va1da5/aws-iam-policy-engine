import { createLazyFileRoute, useNavigate } from "@tanstack/react-router";
import Markdown from "react-markdown";
import { Button } from "@/components/ui/button";

export const Route = createLazyFileRoute("/")({
  component: Index,
});

function Index() {
  const navigate = useNavigate({ from: "/" });

  return (
    <div className="prose mx-auto mb-28 w-full lg:prose-xl">
      <Markdown>
        {`
## 👋 Welcome!

Greetings, fellow adventurer! Welcome to this page. Here, you’re about to embark on a journey filled with AWS IAM-related challenges that will put your skills to the test. So, buckle up and prepare to flex those brain muscles while you learn something new.

AWS IAM is a fundamental pillar of public cloud security. It serves as the de facto barrier between your application and the vast expanse of the public internet. Misconfigurations within IAM can lead to access vulnerabilities, providing malicious actors with opportunities to exploit them. The consequences of such oversights can be quite severe, so it’s wise to invest time in grasping IAM concepts to mitigate associated risks. Understanding the intricacies of IAM policies is paramount; it empowers you to craft them more effectively and ensures that no overly permissive access is granted.

These challenges will help you familiarize yourself with AWS IAM policies and introduce you to important concepts that will enhance your understanding when crafting your own policies. Now, let’s dive in and conquer these challenges together!
`}
      </Markdown>

      <div className="flex w-full justify-center pt-5">
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
          Begin Challenge!
        </Button>
      </div>
    </div>
  );
}
