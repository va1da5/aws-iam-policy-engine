import { TestCase as TC } from "@/types";
import {
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "./ui/accordion";
import { Badge } from "@/components/ui/badge";

type Props = {
  testCase: TC;
  outcome: boolean | undefined;
};

const getActualAction = (action: boolean | undefined) => {
  switch (action) {
    case true:
      return "Allowed";
    case false:
      return "Explicitly Denied";
    default:
      return "Implicitly Denied";
  }
};

export default function TestCase({ testCase, outcome }: Props) {
  const { action } = testCase.context;

  const testPassed = outcome
    ? outcome === testCase.allow
    : [false, undefined].includes(testCase.allow);

  return (
    <AccordionItem value={`${JSON.stringify(testCase.context)}`}>
      <AccordionTrigger>
        <span className="flex gap-2">
          <Badge variant={testPassed ? "success" : "failure"}>
            {testPassed ? "Passed" : "Failed"}
          </Badge>
          <span>{action}</span>
        </span>
      </AccordionTrigger>
      <AccordionContent>
        <p>
          <strong>Expected:</strong> {testCase.allow ? "Allowed" : "Denied"}
        </p>
        <p>
          <strong>Actual:</strong> {getActualAction(outcome)}
        </p>
        <p>
          <strong>Context:</strong>
        </p>
        <pre className="text-wrap rounded bg-slate-100 p-2 text-sm">
          {JSON.stringify(testCase.context, null, 2)}
        </pre>
      </AccordionContent>
    </AccordionItem>
  );
}
