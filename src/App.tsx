import exercise from "./assets/3.json";

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

function App() {
  const [policyData, setPolicyData] = useState<string>("");
  const [error, setError] = useState<string>("");
  const [allow, setAllow] = useState<(boolean | undefined)[]>([]);
  const [stats, setStats] = useState({ failed: 0, passed: 0 });
  const [cases, setCases] = useState<TC[]>([]);

  useEffect(() => {
    const testCases = getTestCases(exercise as Exercise);
    setCases(testCases);
    setStats({
      failed: testCases.length,
      passed: 0,
    });

    setPolicyData(JSON.stringify(exercise.initialTemplate, null, 2));
  }, [exercise]);

  useEffect(() => {
    if (!policyData.length) return;

    try {
      const policyObject: Policy = JSON.parse(policyData as string);
      const policy = new IAMPolicyEngine(
        policyObject,
        exercise.policyType as PolicyType,
      );
      const results = cases.map((item) => policy.evaluate(item.context));
      const outcome = cases.map((item, index) => item.allow === results[index]);
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

  return (
    <div className="container m-4 mx-auto w-full">
      <div>
        <h1 className="mb-2 text-2xl">{exercise.name}</h1>
      </div>
      <div className="grid grid-cols-2 gap-6">
        <div className="w-full">
          <div className="rounded border border-solid border-zinc-200">
            <Editor
              value={policyData as string}
              onChange={policyData.length > 0 ? setPolicyData : () => {}}
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
            <Button>Next</Button>
          </Status>

          <div className="mb-10"></div>

          <div className="max-h-[calc(100vh-14rem)] overflow-auto">
            <Accordion type="single" collapsible className="w-full">
              {cases.map((item, index) => {
                return (
                  <TestCase
                    testCase={item}
                    key={index}
                    allowed={allow[index]}
                  />
                );
              })}
            </Accordion>
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
