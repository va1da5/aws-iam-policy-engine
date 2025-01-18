import Markdown from "./markdown";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";

type Props = {
  solution: string;
  status: {
    passed: number;
    failed: number;
  };
  children?: React.ReactNode;
};

export default function Solution({ solution, status, children }: Props) {
  return (
    <Dialog>
      <DialogTrigger
        disabled={status.failed !== 0}
        className="inline-flex h-9 items-center justify-center gap-2 whitespace-nowrap rounded-md bg-slate-600 px-4 py-2 text-sm font-medium text-white shadow-sm transition-colors hover:bg-slate-600/80 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0"
      >
        Solve
      </DialogTrigger>
      <DialogContent className="max-h-[calc(100%-100px)] overflow-y-auto p-8 pb-14 lg:max-w-4xl">
        <DialogHeader>
          <div className="flex w-full justify-center">
            <div>
              <DialogTitle>
                You have successfully solved this challenge!
              </DialogTitle>
              <br />
              <Markdown className="lg:prose-lg">{solution}</Markdown>
              {children}
            </div>
          </div>
        </DialogHeader>
      </DialogContent>
    </Dialog>
  );
}
