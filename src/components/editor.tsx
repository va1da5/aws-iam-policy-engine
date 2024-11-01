import CodeMirror from "@uiw/react-codemirror";
import { json, jsonParseLinter } from "@codemirror/lang-json";
import { linter } from "@codemirror/lint";

type Props = {
  value: string;
  onChange: (value: string) => void;
};

export default function Editor({ value, onChange }: Props) {
  return (
    <CodeMirror
      value={value}
      height="400px"
      extensions={[json(), linter(jsonParseLinter())]}
      onChange={(value) => {
        onChange(value);
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
