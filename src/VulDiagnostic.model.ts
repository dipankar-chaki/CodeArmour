import * as vscode from "vscode";

export type FunctionsListType = {
  functions: Array<string>;
  vulnFunctions: Array<string>;
  shift: Array<Array<number>>;
  range: Array<vscode.Range>;
};

export enum DebugTypes {
  error = "Error",
  info = "Info",
}

export function debugMessage(type: string, message: string) {
  console.log("[" + type + "] [" + new Date().toISOString() + "] " + message);
}
