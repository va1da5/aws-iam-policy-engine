import { TestCase as TC } from "@/types";
import {
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "./ui/accordion";
import { Badge } from "@/components/ui/badge";

type Props = {
  testCase: TC;
  allowed: boolean;
};

export default function TestCase({ testCase, allowed }: Props) {
  const { action } = testCase.context;

  const passed = allowed === testCase.allow;

  return (
    <AccordionItem value={`${JSON.stringify(testCase.context)}`}>
      <AccordionTrigger>
        <span className="flex gap-2">
          <Badge variant={passed ? "success" : "failure"}>
            {passed ? "Passed" : "Failed"}
          </Badge>
          <span>{action}</span>
        </span>
      </AccordionTrigger>
      <AccordionContent>
        <p>
          <strong>Expected:</strong> {testCase.allow ? "Allowed" : "Denied"}
        </p>
        <p>
          <strong>Actual:</strong> {allowed ? "Allowed" : "Denied"}
        </p>
        <p>
          <strong>Context:</strong>
        </p>
        <pre className="rounded bg-slate-100 p-2 text-sm">
          {JSON.stringify(testCase.context, null, 2)}
        </pre>
      </AccordionContent>
    </AccordionItem>
  );
}
