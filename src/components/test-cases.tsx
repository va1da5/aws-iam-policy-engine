import React from "react";
import { TestCase as TC } from "@/types";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "./ui/collapsible";
import { ChevronDown } from "lucide-react";
import { Accordion } from "@radix-ui/react-accordion";
import TestCase from "./test-case";

type Props = {
  cases: TC[];
  results: (boolean | undefined)[];
};

export default function TestCases({ cases, results }: Props) {
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
          <div className="max-h-[calc(100vh-380px)] overflow-auto">
            <p className="text-left text-sm text-muted-foreground">
              Each request context comes with variables that might be needed for
              policy execution. It does not include all of the context values
              available in AWS requests; it only provides those that might be
              needed to complete the policy writing exercise.
            </p>
            <Accordion type="single" collapsible className="w-full">
              {cases.map((item, index) => {
                return (
                  <TestCase
                    testCase={item}
                    key={index}
                    outcome={results[index]}
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
