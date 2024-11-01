import initialPolicy from "./assets/policy.json";
import cases from "./assets/cases.json";

import { useEffect, useState } from "react";
import { IAMPolicyEngine } from "./engine";
import { Policy } from "./engine/types";
import Editor from "./components/editor";

function App() {
  const [policyData, setPolicyData] = useState(
    JSON.stringify(initialPolicy, null, 2),
  );
  const [error, setError] = useState<string>("");
  const [results, setResults] = useState<boolean[]>([]);

  useEffect(() => {
    try {
      const policyObject: Policy = JSON.parse(policyData);
      const policy = new IAMPolicyEngine(policyObject);
      setResults(cases.map((item) => policy.evaluate(item.requestContext)));
      setError("");
    } catch (e) {
      setError(e.message);
    }
  }, [policyData]);

  return (
    <div className="container m-4 mx-auto w-full">
      <div className="grid grid-cols-2 gap-6">
        <div className="w-full">
          <div className="relative max-h-[400px]">
            <Editor value={policyData} onChange={setPolicyData} />
          </div>

          {error.length > 0 && (
            <pre className="mt-2 text-wrap break-words bg-red-100 p-2 text-sm">
              {error}
            </pre>
          )}
        </div>

        <div className="w-full">
          {cases.map((item, index) => {
            return (
              <div
                className="mb-2 block rounded-lg border border-gray-200 bg-white p-6 shadow hover:bg-gray-100 dark:border-gray-700 dark:bg-gray-800 dark:hover:bg-gray-700"
                key={index}
              >
                {(results[index] && (
                  <span className="me-3 flex h-3 w-3 rounded-full bg-green-500"></span>
                )) || (
                  <span className="me-3 flex h-3 w-3 rounded-full bg-red-500"></span>
                )}
                <ul>
                  {Object.keys(item.requestContext).map((element) => (
                    <li key={element}>
                      {element}: {item.requestContext[element]}
                    </li>
                  ))}
                </ul>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

export default App;
