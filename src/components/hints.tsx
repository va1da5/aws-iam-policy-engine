import { useState } from "react";
import Markdown from "./markdown";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "./ui/collapsible";
import { ChevronDown, Eye } from "lucide-react";

type Props = {
  values: string[];
};

export default function Hints({ values }: Props) {
  const [hidden, setHidden] = useState(values.map(() => true));
  return (
    <div className="w-full rounded border p-4">
      <Collapsible>
        <CollapsibleTrigger className="w-full">
          <span className="mb-1 flex w-full justify-between">
            <div>
              <p className="text-left font-medium">Hints</p>
              <p className="text-left text-sm text-muted-foreground">
                Click to expand the list of hints
              </p>
            </div>
            <div>
              <ChevronDown />
            </div>
          </span>
        </CollapsibleTrigger>

        <CollapsibleContent>
          {values.map((hint, index) => {
            return (
              <div key={index} className="relative my-1 p-2">
                {hidden[index] && (
                  <div className="absolute bottom-0 left-0 right-0 top-0 flex justify-center align-middle backdrop-blur-sm">
                    <button
                      title="Show hint"
                      className="hover:text-blue-700"
                      onClick={() =>
                        setHidden((current) =>
                          current.map((item, idx) =>
                            index === idx ? false : item,
                          ),
                        )
                      }
                    >
                      <Eye size={32} />
                    </button>
                  </div>
                )}
                <Markdown>{hint}</Markdown>
              </div>
            );
          })}
        </CollapsibleContent>
      </Collapsible>
    </div>
  );
}
