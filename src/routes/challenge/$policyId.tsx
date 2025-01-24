import { useEffect, useState } from "react";
import { IAMPolicyEngine } from "@/engine";
import { Policy } from "@/engine/types";
import Editor from "@/components/editor";
import { Exercise, TestCase as TC } from "@/types";
import { getTestCases } from "@/utils/prepareTestCases";
import Status from "@/components/status";
import { Button } from "@/components/ui/button";
import { getErrorMessage, getPolicyType } from "@/engine/utils";
import { useQuery } from "@tanstack/react-query";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import Hints from "@/components/hints";
import TestCases from "@/components/test-cases";
import Markdown from "@/components/markdown";
import Solution from "@/components/solution";
import { numberOfChallenges } from "@/constants";
import { setActiveChallenge } from "@/utils/tracker";

export const Route = createFileRoute("/challenge/$policyId")({
  component: Challenge,
});

function Challenge() {
  const { policyId } = Route.useParams();
  const navigate = useNavigate();
  const [currentPolicy, setCurrentPolicy] = useState<string>("");
  const [error, setError] = useState<string>("");
  const [results, setResults] = useState<(boolean | undefined)[]>([]);
  const [status, setStatus] = useState({ failed: 0, passed: 0 });
  const [cases, setCases] = useState<TC[]>([]);

  const {
    isPending,
    error: fetchError,
    data: exercise,
    isFetching,
  } = useQuery({
    queryKey: [policyId],
    queryFn: async () => {
      const response = await fetch(`/policies/${policyId}.json`);
      return await response.json();
    },
    retry: 1,
  });

  useEffect(() => {
    setStatus({
      failed: 1,
      passed: 0,
    });
    setCurrentPolicy("");
  }, [policyId]);

  useEffect(() => {
    if (isPending || isFetching || fetchError) return;

    const testCases = getTestCases(exercise as Exercise);
    setCases(testCases);
    setStatus({
      failed: testCases.length,
      passed: 0,
    });
  }, [exercise, isPending, isFetching]);

  useEffect(() => {
    if (isPending || isFetching) return;
    if (!currentPolicy.length) return;

    try {
      const policyObject: Policy = JSON.parse(currentPolicy as string);

      const policy = new IAMPolicyEngine(policyObject, exercise.policyType);
      const results = cases.map((item) => policy.evaluate(item.context));
      const outcome = cases.map(
        (item, index) =>
          item.allow === results[index] ||
          (item.allow === false && results[index] === undefined),
      );
      const failed = outcome.filter((item) => !item).length;
      const passed = outcome.filter((item) => item).length;
      setResults(results);
      setStatus({
        failed,
        passed,
      });
      setError("");
    } catch (error) {
      setError(getErrorMessage(error));
      setResults([]);
      setStatus({
        failed: cases.length,
        passed: 0,
      });
    }
  }, [currentPolicy, exercise, isPending, isFetching]);

  if (isPending || isFetching) return "Loading...";

  if (fetchError) {
    return navigate({
      to: Route.to,
      replace: true,
      params: {
        policyId: "error",
      },
    });
  }

  return (
    <div>
      <div className="mb-2 grid grid-cols-2 gap-6">
        <div className="">
          <h1 className="text-lg">
            Level {policyId}. {exercise.name}
          </h1>
          <h2 className="font-bold">{getPolicyType(exercise.policyType)}</h2>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-6">
        <div className="w-full">
          <div className="group relative rounded border border-solid border-zinc-200">
            <Editor
              value={JSON.stringify(exercise.initialPolicy, null, 2)}
              onChange={setCurrentPolicy}
            />
            {error.length > 0 && (
              <pre className="absolute bottom-0 mt-2 w-full text-wrap break-words rounded bg-red-100 p-2 text-sm opacity-100 transition-opacity duration-300 ease-in-out group-hover:pointer-events-none group-hover:opacity-80">
                {error}
              </pre>
            )}
          </div>

          <div className="mt-5">
            <p className="text-lg font-medium">Challenge</p>
            <div className="prose prose-slate w-full dark:prose-invert prose-p:my-2 prose-ul:mt-0 prose-li:m-0">
              <Markdown>{exercise.description}</Markdown>
            </div>
          </div>
        </div>

        <div className="w-full">
          <Status status={status}>
            <div className="flex gap-2">
              {!isPending && (
                <Solution solution={exercise.solution} status={status}>
                  <div className="mt-10 flex w-full justify-center">
                    {parseInt(policyId) < numberOfChallenges && (
                      <Button
                        onClick={() => {
                          setActiveChallenge(parseInt(policyId) + 1);
                          navigate({
                            from: `/challenge/${policyId}`,
                            to: Route.to,
                            replace: true,
                            params: {
                              policyId: String(parseInt(policyId) + 1),
                            },
                          });
                        }}
                      >
                        Next Challenge
                      </Button>
                    )}

                    {parseInt(policyId) >= numberOfChallenges && (
                      <Button
                        onClick={() => {
                          setActiveChallenge(1);
                          navigate({
                            from: `/challenge/${policyId}`,
                            to: "/finish",
                            replace: true,
                          });
                        }}
                      >
                        Finish
                      </Button>
                    )}
                  </div>
                </Solution>
              )}
            </div>
          </Status>

          <div className="mb-5"></div>

          {exercise.hints.length > 0 && (
            <div>
              <Hints values={exercise.hints} />
              <div className="mb-5"></div>
            </div>
          )}

          <TestCases cases={cases} results={results} />
        </div>
      </div>
    </div>
  );
}
