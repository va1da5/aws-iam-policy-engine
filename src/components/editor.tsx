import CodeMirror from "@uiw/react-codemirror";
import { json, jsonParseLinter } from "@codemirror/lang-json";
import { linter } from "@codemirror/lint";
import { useEffect, useState } from "react";

type Props = {
  value: string;
  onChange: (value: string) => void;
  debounce?: number;
};

export default function Editor({ value, onChange, debounce = 1000 }: Props) {
  const [state, setState] = useState(value);

  useEffect(() => {
    setState(value);
  }, [value]);

  useEffect(() => {
    const timeout = setTimeout(() => {
      onChange(state);
    }, debounce);

    return () => clearTimeout(timeout);
  }, [state, debounce, onChange, value]);

  return (
    <CodeMirror
      value={value}
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
  );
}
