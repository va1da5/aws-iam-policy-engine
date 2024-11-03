import { Exercise } from "@/types";

export function getTestCases(exercise: Exercise) {
  return exercise.testCases
    .map((testCase) => {
      const jsonData = JSON.stringify(testCase);
      if (!jsonData.includes("${")) {
        return testCase;
      }

      const [first, ...restVariables] = getPolicyVariables(jsonData);

      return exercise.values[first].map((value, index) => {
        let newJSONData = applyVariable(jsonData, first, value);
        if (restVariables.length > 0) {
          for (const variable of restVariables) {
            newJSONData = applyVariable(
              newJSONData,
              variable,
              exercise.values[variable][index],
            );
          }
        }

        return JSON.parse(newJSONData);
      });
    })
    .flat();
}

function applyVariable(current: string, name: string, value: string) {
  return current.replace(new RegExp(`\\$\\{${name}\\}`, "g"), value);
}

function getPolicyVariables(json: string) {
  const regex = /\$\{([^}]+)\}/g;
  const matches = [];
  let match;

  while ((match = regex.exec(json)) !== null) {
    matches.push(match[1]);
  }
  return matches;
}
