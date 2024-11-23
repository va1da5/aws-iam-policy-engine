import { cn } from "@/lib/utils";
import ReactMarkdown from "react-markdown";

type Props = {
  children: string;
  className?: string;
};

export default function Markdown({ className, children }: Props) {
  return (
    <div className={cn("prose", className)}>
      <ReactMarkdown
        components={{
          a(props) {
            const { href, children } = props;
            return (
              <a href={href} target="_blank" rel="noopener noreferrer">
                {children}
              </a>
            );
          },
        }}
      >
        {children}
      </ReactMarkdown>
    </div>
  );
}
