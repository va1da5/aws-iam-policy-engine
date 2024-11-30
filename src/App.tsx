import { useEffect, useState } from "react";
import { IAMPolicyEngine } from "./engine";
import { Policy, PolicyType } from "./engine/types";
import Editor from "./components/editor";
import { Exercise, TestCase as TC } from "./types";
import { getTestCases } from "./utils/prepareTestCases";
import { Accordion } from "./components/ui/accordion";
import TestCase from "@/components/test-case";
import Status from "./components/status";
import { Button } from "./components/ui/button";
import { getErrorMessage } from "./engine/utils";
import { useQuery } from "@tanstack/react-query";
import NavBar from "./components/navbar";
import { Collapsible, CollapsibleContent } from "./components/ui/collapsible";
import { CollapsibleTrigger } from "@radix-ui/react-collapsible";
import { ChevronDown } from "lucide-react";

function App() {
  const [policyData, setPolicyData] = useState<string>("");
  const [error, setError] = useState<string>("");
  const [allow, setAllow] = useState<(boolean | undefined)[]>([]);
  const [stats, setStats] = useState({ failed: 0, passed: 0 });
  const [cases, setCases] = useState<TC[]>([]);
  const [policy, setPolicy] = useState(1);

  const {
    isPending,
    error: fetchError,
    data: exercise,
    isFetching,
  } = useQuery({
    queryKey: [policy],
    queryFn: async () => {
      const response = await fetch(`/policies/${policy}.json`);
      return await response.json();
    },
  });

  useEffect(() => {
    if (isPending) return;

    const testCases = getTestCases(exercise as Exercise);
    setCases(testCases);
    setStats({
      failed: testCases.length,
      passed: 0,
    });

    setPolicyData(JSON.stringify(exercise.initialPolicy, null, 2));
  }, [exercise, isPending]);

  useEffect(() => {
    if (isPending) return;
    if (!policyData.length) return;

    try {
      const policyObject: Policy = JSON.parse(policyData as string);

      const policy = new IAMPolicyEngine(
        policyObject,
        exercise.policyType as PolicyType,
      );
      const results = cases.map((item) => policy.evaluate(item.context));
      const outcome = cases.map(
        (item, index) =>
          item.allow === results[index] || results[index] === undefined,
      );
      const failed = outcome.filter((item) => !item).length;
      const passed = outcome.filter((item) => item).length;
      setAllow(results);
      setStats({
        failed,
        passed,
      });
      setError("");
    } catch (error) {
      setError(getErrorMessage(error));
      setAllow([]);
      setStats({
        failed: cases.length,
        passed: 0,
      });
    }
  }, [policyData]);

  if (isPending) return "";

  return (
    <div className="container m-4 mx-auto w-full">
      <NavBar />
      <div className="mb-10"></div>
      <div>
        <h1 className="mb-2 text-xl">{exercise.name}</h1>
      </div>
      <div className="grid grid-cols-2 gap-6">
        <div className="w-full">
          <div className="rounded border border-solid border-zinc-200">
            <Editor
              value={policyData as string}
              onChange={
                policyData.length > 0 && !isPending ? setPolicyData : () => {}
              }
            />
          </div>

          {error.length > 0 && (
            <pre className="mt-2 text-wrap break-words rounded bg-red-100 p-2 text-sm">
              {error}
            </pre>
          )}

          <p className="my-2">{exercise.description}</p>
        </div>

        <div className="w-full">
          <Status passed={stats.passed} failed={stats.failed}>
            <div className="flex gap-2">
              <Button>Solve</Button>
              <Button onClick={() => setPolicy((current) => current + 1)}>
                Next
              </Button>
            </div>
          </Status>

          <div className="mb-10"></div>

          <div className="w-full rounded border p-4">
            <Collapsible>
              <CollapsibleTrigger className="w-full">
                <span className="mb-1 flex w-full justify-between">
                  <div>
                    <p className="text-left font-medium">Evaluation Requests</p>
                    <p className="text-left text-sm text-muted-foreground">
                      Click to expand the list of simulated request contexts
                      that are used for the created IAM policy. Each entry comes
                      with variables that might be needed for policy execution.
                      It does not include all of the context values available in
                      AWS requests; it only provides those that might be needed
                      to complete the policy writing exercise.
                    </p>
                  </div>
                  <div>
                    <ChevronDown />
                  </div>
                </span>
              </CollapsibleTrigger>

              <CollapsibleContent>
                <div className="max-h-[calc(100vh-30rem)] overflow-auto">
                  <Accordion type="single" collapsible className="w-full">
                    {cases.map((item, index) => {
                      return (
                        <TestCase
                          testCase={item}
                          key={index}
                          outcome={allow[index]}
                        />
                      );
                    })}
                  </Accordion>
                </div>
              </CollapsibleContent>
            </Collapsible>
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
