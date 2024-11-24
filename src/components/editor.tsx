import CodeMirror from "@uiw/react-codemirror";
import { json, jsonParseLinter } from "@codemirror/lang-json";
import { linter } from "@codemirror/lint";
import { useEffect, useState } from "react";
import { Braces } from "lucide-react";

type Props = {
  value: string;
  onChange: (value: string) => void;
  debounce?: number;
};

export default function Editor({ value, onChange, debounce = 1000 }: Props) {
  const [state, setState] = useState(value);

  useEffect(() => {
    setState(value);
    onChange(value);
  }, [value, onChange]);

  useEffect(() => {
    const timeout = setTimeout(() => {
      onChange(state);
    }, debounce);

    return () => clearTimeout(timeout);
  }, [state, debounce, onChange, value]);

  const prettifyJson = () => {
    try {
      const json = JSON.parse(state);
      setState(JSON.stringify(json, null, 2));
    } catch (error) {
      console.error(error);
    }
  };

  return (
    <div className="relative">
      <button
        title="Beautify policy"
        className="absolute right-4 top-3 z-10 text-gray-400 transition-all hover:text-blue-700"
        onClick={prettifyJson}
      >
        <Braces />
      </button>
      <CodeMirror
        value={state}
        height="400px"
        extensions={[json(), linter(jsonParseLinter())]}
        onChange={(value) => {
          setState(value);
        }}
        basicSetup={{
          lineNumbers: true,
          foldGutter: true,
          dropCursor: true,
          allowMultipleSelections: true,
          indentOnInput: false,
          lintKeymap: true,
        }}
      />
    </div>
  );
}
