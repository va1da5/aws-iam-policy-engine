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
  children?: React.ReactNode;
};

export default function Solution({ solution, children }: Props) {
  return (
    <Dialog>
      <DialogTrigger className="inline-flex h-9 items-center justify-center gap-2 whitespace-nowrap rounded-md bg-green-600 px-4 py-2 text-sm font-medium text-white shadow-sm transition-colors hover:bg-green-600/80 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0">
        Solve
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>
            You have successfully solved this challenge!
          </DialogTitle>

          <div>
            <Markdown>{solution}</Markdown>
            {children}
          </div>
        </DialogHeader>
      </DialogContent>
    </Dialog>
  );
}
