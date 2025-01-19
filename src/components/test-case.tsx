import { TestCase as TC } from "@/types";
import {
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "./ui/accordion";
import { Badge } from "@/components/ui/badge";
import Indicator from "./indicator";
import { parseBool } from "@/engine/utils";

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

const getExpectedAction = (allow: boolean) => {
  return allow ? "Allowed" : "Denied";
};

export default function TestCase({ testCase, outcome }: Props) {
  const { action } = testCase.context;

  const testPassed = outcome
    ? outcome === testCase.allow
    : [false, undefined].includes(testCase.allow);

  return (
    <AccordionItem value={`${JSON.stringify(testCase.context)}`}>
      <AccordionTrigger className="hover:no-underline">
        <span className="flex w-full gap-2 hover:no-underline">
          <Badge variant={testPassed ? "success" : "failure"}>
            {testPassed ? "Passed" : "Failed"}
          </Badge>
          <span className="flex w-full justify-between pr-5">
            <span className="hover:underline">{action}</span>
            <span className="flex gap-3">
              <Indicator
                state={testCase.allow}
                tooltip={`Expected policy outcome is "${getExpectedAction(testCase.allow)}"`}
              />
              <Indicator
                state={parseBool(outcome)}
                tooltip={`Current policy outcome is "${getActualAction(outcome)}"`}
              />
            </span>
          </span>
        </span>
      </AccordionTrigger>
      <AccordionContent>
        <p>
          <strong>Expected:</strong> {getExpectedAction(testCase.allow)}
        </p>
        <p>
          <strong>Actual:</strong> {getActualAction(outcome)}
        </p>
        <p>
          <strong>Request Context:</strong>
        </p>
        <pre className="text-wrap rounded bg-slate-100 p-2 text-sm">
          {JSON.stringify(testCase.context, null, 2)}
        </pre>
      </AccordionContent>
    </AccordionItem>
  );
}
