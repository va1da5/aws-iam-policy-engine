export type Policy = {
  Version: "2008-10-17" | "2012-10-17";
  Statement: Statement[];
  Id?: string;
};

export type PolicyType = "identity-based" | "resource-based" | "trust";

export type Statement = {
  Sid?: string;
  Effect: Effect;
  Principal?: Principal;
  NotPrincipal?: Principal;
  Action: Action;
  Resource?: Resource;
  NotResource?: Resource;
  Condition?: Condition;
  NotAction?: Action;
};

export type Effect = "Allow" | "Deny";
export type Action = string[] | string;
export type Resource = string[] | string;

export type Principal =
  | {
      AWS?: string | string[];
      Service?: string | string[];
      CanonicalUser?: string | string[];
      Federated?: string | string[];
      [key: string]: string | string[] | undefined;
    }
  | string;

export type Condition = {
  [key: string]: {
    [key: string]: string | string[];
  };
};

export type RequestContext = {
  action: string;
  resource?: string;
  principal?: { [key: string]: string | string[] };
  [key: string]:
    | string
    | string[]
    | { [key: string]: string | string[] }
    | undefined;
};
