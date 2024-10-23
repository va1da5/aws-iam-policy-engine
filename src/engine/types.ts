export type Policy = {
  Version: string;
  Statement: Statement[];
  Id?: string;
};

export type Statement = {
  Sid?: string;
  Effect: Effect;
  Principal?: Principal;
  Action: Action;
  Resource: Resource;
  Condition?: Condition;
  NotAction?: Action;
  NotResource?: Resource;
};

export type Effect = "Allow" | "Deny";
export type Action = string[] | string;
export type Resource = string[] | string;

export type Principal = {
  AWS?: string[];
  Service?: string[];
};

export type Condition = {
  [key: string]: {
    [key: string]: string | string[];
  };
};

export type RequestContext = {
  action: string;
  resource: string;
  [key: string]: string | string[];
};
