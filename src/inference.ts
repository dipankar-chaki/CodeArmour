import path = require("path");
import { VulDiagnostic } from "./VulDiagnostic";
import { DebugTypes, debugMessage } from "./VulDiagnostic.model";
import { PythonShell } from "python-shell";

const axios = require("axios");

export interface Inference {
  line(list: Array<string>): Promise<any>;
  cwe(list: Array<string>): Promise<any>;
  desc(list: Array<string>): Promise<any>;
}

export class LocalInference implements Inference {
  targetDiagnostic: VulDiagnostic;

  constructor(targetDiagnostic: VulDiagnostic) {
    this.targetDiagnostic = targetDiagnostic;
  }
  scriptLocation: string = path.join(
    __dirname,
    "..",
    "resources",
    // "local-inference",
  );

  // Request for vulnerablity classification model
  public async line(list: Array<string>): Promise<any> {
    if (this.targetDiagnostic.ignore) {
      return Promise.resolve();
    }

    debugMessage(DebugTypes.info, "Starting line inference");

    const shell = new PythonShell("local.py", {
      mode: "text",
      args: ["line"],
      scriptPath: this.scriptLocation,
    });

    debugMessage(DebugTypes.info, "Sending data to python script");
    let start = new Date().getTime();
    shell.send(JSON.stringify(list));

    return new Promise((resolve, reject) => {
      shell.on("message", async (message: any) => {
        let end = new Date().getTime();
        debugMessage(
          DebugTypes.info,
          "Received response from python script in " + (end - start) + "ms",
        );
        this.targetDiagnostic.predictions.line = JSON.parse(message);
        resolve(JSON.parse(message));
      });

      shell.end((err: any) => {
        if (err) {
          reject(err);
        }
      });
    });
  }

  // Request for cwe assignment model
  public async cwe(list: Array<string>): Promise<any> {
    if (this.targetDiagnostic.ignore) {
      return Promise.resolve();
    }

    debugMessage(DebugTypes.info, "Starting CWE prediction");

    const shell = new PythonShell("local.py", {
      mode: "text",
      args: ["cwe"],
      scriptPath: this.scriptLocation,
    });

    debugMessage(DebugTypes.info, "Sending data to python script");
    let start = new Date().getTime();
    shell.send(JSON.stringify(list));

    return new Promise((resolve, reject) => {
      shell.on("message", async (message: any) => {
        let end = new Date().getTime();
        debugMessage(
          DebugTypes.info,
          "Received response from python script in " + (end - start) + "ms",
        );
        this.targetDiagnostic.predictions.cwe = JSON.parse(message);
        resolve(JSON.parse(message));
      });

      shell.end((err: any) => {
        if (err) {
          reject(err);
        }
      });
    });
  }

  // Requst for description generation model
  public async desc(list: Array<string>): Promise<any> {
    if (this.targetDiagnostic.ignore) {
      return Promise.resolve();
    }

    debugMessage(DebugTypes.info, "Starting Description Generation");

    const shell = new PythonShell("local.py", {
      mode: "text",
      args: ["description"],
      scriptPath: this.scriptLocation,
    });

    debugMessage(DebugTypes.info, "Sending data to python script");
    let start = new Date().getTime();
    shell.send(JSON.stringify(list));

    return new Promise((resolve, reject) => {
      shell.on("message", async (message: any) => {
        let end = new Date().getTime();
        debugMessage(
          DebugTypes.info,
          "Received response from python script in " + (end - start) + "ms",
        );
        this.targetDiagnostic.predictions.desc =
          JSON.parse(message).description;
        resolve(JSON.parse(message));
      });

      shell.end((err: any) => {
        if (err) {
          reject(err);
        }
      });
    });
  }
}
