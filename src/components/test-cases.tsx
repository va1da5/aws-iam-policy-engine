import { TestCase as TC } from "@/types";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "./ui/collapsible";
import { ChevronDown } from "lucide-react";
import { Accordion } from "@radix-ui/react-accordion";
import TestCase from "./test-case";
import { useMemo } from "react";

type Props = {
  cases: TC[];
  results: (boolean | undefined)[];
};

function didPass(testCase: TC, outcome: boolean | undefined) {
  return outcome
    ? outcome === testCase.allow
    : [false, undefined].includes(testCase.allow);
}

export default function TestCases({ cases, results }: Props) {
  const outcomes = useMemo(
    () =>
      cases
        .map((testCase, index) => ({ testCase, outcome: results[index] }))
        .sort((a, b) => {
          if (didPass(a.testCase, a.outcome) === didPass(b.testCase, b.outcome))
            return 0;

          if (didPass(a.testCase, a.outcome)) return 1;

          return -1;
        }),
    [cases, results],
  );

  return (
    <div className="w-full rounded border p-4">
      <Collapsible>
        <CollapsibleTrigger className="w-full">
          <span className="mb-1 flex w-full justify-between">
            <div>
              <p className="text-left font-medium">Evaluation Requests</p>
              <p className="text-left text-sm text-muted-foreground">
                Click to expand the list of simulated request contexts.
              </p>
            </div>
            <div>
              <ChevronDown />
            </div>
          </span>
        </CollapsibleTrigger>

        <CollapsibleContent>
          <div className="max-h-[calc(100vh-100px)] overflow-auto">
            <p className="text-left text-sm text-muted-foreground">
              Each request context comes with variables that might be needed for
              policy execution. It does not include all of the context values
              available in AWS requests; it only provides those that might be
              needed to complete the policy writing exercise.
            </p>
            <Accordion type="single" collapsible className="w-full">
              {outcomes.map((item, index) => {
                return (
                  <TestCase
                    testCase={item.testCase}
                    key={index}
                    outcome={item.outcome}
                  />
                );
              })}
            </Accordion>
          </div>
        </CollapsibleContent>
      </Collapsible>
    </div>
  );
}
