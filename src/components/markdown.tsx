import { cn } from "@/lib/utils";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";

type Props = {
  children: string;
  className?: string;
};

export default function Markdown({ className, children }: Props) {
  return (
    <div className={cn("prose", className)}>
      <ReactMarkdown
        remarkPlugins={[[remarkGfm, { singleTilde: false }]]}
        components={{
          a(props) {
            const { href, children } = props;
            return (
              <a href={href} target="_blank" rel="noopener noreferrer">
                {children}
              </a>
            );
          },
          pre(props) {
            const { children, className } = props;
            return <pre className={cn("not-prose", className)}>{children}</pre>;
          },
          code(props) {
            const { children, className } = props;
            const match = /language-(\w+)/.exec(className || "");
            return match ? (
              <div className="not-prose text-sm">
                <SyntaxHighlighter
                  PreTag="div"
                  children={String(children).replace(/\n$/, "")}
                  language={match[1]}
                />
              </div>
            ) : (
              <code className={cn("not-prose", className)}>{children}</code>
            );
          },
        }}
      >
        {children}
      </ReactMarkdown>
    </div>
  );
}
