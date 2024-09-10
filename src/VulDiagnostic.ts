import * as vscode from "vscode";
import * as path from "path";
import { LocalInference } from "./inference";
import {
  debugMessage,
  DebugTypes,
  FunctionsListType,
} from "./VulDiagnostic.model";
import { cweXMLFile, fsa, parser, progressEmitter } from "./extension";
import { VulnerabilitiesPanel } from "./vulnerabilitiesPanel";
import {
  VulnerableFileType,
  VulnerabilityType,
} from "./vulnerabilitiesPanel.models";

export class VulDiagnostic {
  targetDocument: vscode.TextDocument | undefined;
  ignore: boolean = false;
  fileIgnoreFunctions: { [key: string]: string[] };

  functionsList: FunctionsListType = {
    functions: [],
    vulnFunctions: [],
    shift: [],
    range: [],
  };

  predictions: { [key: string]: any } = {
    line: [],
    cwe: [],
    desc: [],
  };

  constructor(
    targetDocument?: vscode.TextDocument,
    fileIgnoreFunctions?: { [key: string]: string[] },
  ) {
    if (targetDocument) {
      this.targetDocument = targetDocument;
    }
    if (fileIgnoreFunctions) {
      this.fileIgnoreFunctions = fileIgnoreFunctions;
    } else {
      this.fileIgnoreFunctions = {};
    }
  }

  // Called to analyse the current text document
  async analysisSequence(diagnosticCollection: vscode.DiagnosticCollection) {
    await this.extractFunctions()
      .then(() => {
        debugMessage(DebugTypes.info, "Finished extracting functions");
      })
      .catch((err) => {
        debugMessage(DebugTypes.error, err);
        return Promise.reject(err);
      });

    await this.inferenceSequence()
      .then(() => {
        debugMessage(DebugTypes.info, "Finished inference");
      })
      .catch((err) => {
        debugMessage(DebugTypes.error, err);
        return Promise.reject(err);
      });

    await this.constructDiagnostics(diagnosticCollection)
      .then(() => {
        debugMessage(DebugTypes.info, "Finished constructing diagnostics");

        // const descriptions = this.predictions.desc;
        // updateVulnerabilitiesPanel(diagnosticCollection, this.targetDocument!.uri, descriptions);
      })
      .catch((err) => {
        debugMessage(DebugTypes.error, err);
        return Promise.reject(err);
      });

    await this.updateSidebarContent()
      .then(() => {
        debugMessage(DebugTypes.info, "Updated sidebar content");
      })
      .catch((err) => {
        debugMessage(DebugTypes.error, err);
        return Promise.reject(err);
      });
  }

  // Extracts functions from text document
  async extractFunctions() {
    const uri = vscode.window.activeTextEditor?.document.uri;

    // Check valid doc
    if (!this.targetDocument || uri === undefined) {
      debugMessage(DebugTypes.error, "No document found");
      return Promise.reject("No document found");
    }

    // Check non-empty doc
    var text = this.targetDocument.getText();
    var lines = text.split(/\r?\n/);

    if (lines.length === 0) {
      debugMessage(DebugTypes.error, "Empty document");
      return Promise.reject("Empty document");
    }

    debugMessage(DebugTypes.info, "Getting Symbols");

    let symbols: vscode.DocumentSymbol[] = [];
    let start = new Date().getTime();
    var period = new Date().getTime();
    while (symbols === undefined || period - start < 3000) {
      symbols = await vscode.commands.executeCommand<vscode.DocumentSymbol[]>(
        "vscode.executeDocumentSymbolProvider",
        uri,
      );
      if (symbols !== undefined) {
        break;
      }
      period = new Date().getTime();
    }

    let end = new Date().getTime();

    // Set timeout
    if (symbols === undefined) {
      debugMessage(DebugTypes.error, "No symbols found after 3 seconds");
      return Promise.reject("No symbols found");
    } else {
      debugMessage(
        DebugTypes.info,
        "Found " + symbols.length + " symbols in " + (end - start) + " ms",
      );
    }
    // Formatting functions before storing
    symbols.forEach((element) => {
      if (element.kind === vscode.SymbolKind.Function) {
        var block: string = "";
        for (
          var i = element.range.start.line;
          i <= element.range.end.line;
          i++
        ) {
          block += lines[i];
          if (i !== element.range.end.line) {
            block += "\n";
          }
        }

        block = this.removeComments(block);
        const result = this.removeBlankLines(block);

        this.functionsList.functions.push(result[0]);
        this.functionsList.shift.push(result[1]);
        this.functionsList.range.push(element.range);
      }
    });
  }

  // Uses models to perform inference on functions
  async inferenceSequence() {
    if (this.targetDocument?.getText() === "") {
      debugMessage(DebugTypes.error, "Document is empty, aborting analysis");
      return Promise.reject("Document is empty, aborting analysis");
    }

    var start = new Date().getTime();

    // Initialise inference engine to send code to model
    let inferenceEngine = new LocalInference(this);

    // Retrieve vulnerable functions
    await inferenceEngine
      .line(this.functionsList.functions)
      .then(() => {
        debugMessage(DebugTypes.info, "Line vulnerabilities retrieved");

        this.predictions.line.batch_vul_pred.forEach(
          (element: any, i: number) => {
            if (element === 1) {
              this.functionsList.vulnFunctions.push(
                this.functionsList.functions[i],
              );
            }
          },
        );
      })
      .catch((err: string) => {
        debugMessage(DebugTypes.error, err);
        return Promise.reject(err);
      });

    // If no vulnerable functions, print logs and complete
    if (this.functionsList.vulnFunctions.length === 0) {
      debugMessage(DebugTypes.info, "No vulnerabilities found");
    } else {
      // If vulnerable functions, call cwe assignment model
      await Promise.all([inferenceEngine.cwe(this.functionsList.vulnFunctions)])
        .then(() => {
          debugMessage(DebugTypes.info, "CWE type retrieved");
        })
        .catch((err: string) => {
          debugMessage(DebugTypes.error, err);
          return Promise.reject(err);
        });
      // Contextual description generation
      await inferenceEngine
        .desc(this.functionsList.vulnFunctions)
        .then(() => {
          debugMessage(DebugTypes.info, "Descriptions generated");
        })
        .catch((err: string) => {
          debugMessage(DebugTypes.error, err);
          return Promise.reject(err);
        });
    }

    var end = new Date().getTime();

    debugMessage(
      DebugTypes.info,
      "All inference completed in " + (end - start) + "ms",
    );

    return Promise.resolve();
  }

  // Construct VS Code diagnostics for hover menu and syntax highlighitng
  async constructDiagnostics(
    diagnosticCollection: vscode.DiagnosticCollection,
  ) {
    if (this.targetDocument === undefined) {
      debugMessage(
        DebugTypes.error,
        "No document found to construct diagnostics",
      );
      return 1;
    }

    if (this.ignore) {
      debugMessage(DebugTypes.info, "Ignoring diagnostics");
      return 0;
    }

    let vulCount = 0;
    let diagnostics: vscode.Diagnostic[] = [];

    let cweList: any[] = [];

    // Push cwe type and id of all vulnerable functions to cweList
    this.predictions.line.batch_vul_pred.forEach((element: any, i: number) => {
      if (element === 1) {
        cweList.push([
          this.predictions.cwe.cwe_type[vulCount],
          this.predictions.cwe.cwe_id[vulCount]?.substring(4),
        ]);
        vulCount++;
      }
    });

    // Reset vulCount for diagnostics construction
    vulCount = 0;

    // Adds 2 new fields in pred.cwe - names and descriptions
    await this.fetchCWEData(cweList);

    this.functionsList.range.forEach((value: any, i: number) => {
      const functionName =
        this.functionsList.functions[i].split("(")[0].split(" ").pop() || "";
      const ignoredFunctionNames = this.targetDocument?.fileName
        ? this.fileIgnoreFunctions[this.targetDocument.fileName] || []
        : [];
      // Check function is vulnerable
      if (
        this.predictions.line.batch_vul_pred[i] === 1 &&
        !ignoredFunctionNames.includes(functionName)
      ) {
        debugMessage(
          DebugTypes.info,
          "Constructing diagnostic for function: " + i,
        );

        // Check vulCount does not exceed the bounds of the cwe arrays
        if (vulCount >= this.predictions.cwe.cwe_id.length) {
          debugMessage(
            DebugTypes.error,
            "VulCount exceeds bounds of cwe arrays for function index " + i,
          );
          return 0;
        }

        // this.functionsList.* contains all functions
        // this.predictions.line contains line predcitions for all functions
        // this.predictions.cwe contains only vulnerable functions

        const cweID = this.predictions.cwe.cwe_id[vulCount];
        const cweIDProb = this.predictions.cwe.cwe_id_prob[vulCount];
        const cweType = this.predictions.cwe.cwe_type[vulCount];
        const cweTypeProb = this.predictions.cwe.cwe_type_prob[vulCount];

        let cweDescription = this.predictions.cwe.descriptions[vulCount];
        const cweName = this.predictions.cwe.names[vulCount];

        const lineScores = this.predictions.line.batch_line_scores[i];

        // Check for undefined CWE ID or Type
        if (!cweID || !cweType) {
          debugMessage(
            DebugTypes.error,
            "CWE ID or Type is undefined for function index " + i,
          );
          return 0;
        }

        let lineScoreShiftMapped: number[][] = [];

        this.functionsList.shift[i].forEach((element: number) => {
          lineScores.splice(element, 0, 0);
        });

        let lineStart = this.functionsList.range[i].start.line;

        lineScores.forEach((element: number, index: number) => {
          const lineNumber = lineStart + index;
          if (
            this.targetDocument &&
            lineNumber >= 0 &&
            lineNumber < this.targetDocument.lineCount
          ) {
            lineScoreShiftMapped.push([lineNumber, element]);
          }
        });

        // Sort by prediction score
        lineScoreShiftMapped.sort((a: number[], b: number[]) => {
          return b[1] - a[1];
        });

        const vulnLine = lineScoreShiftMapped[0][0];
        // ensure that invalid line numbers do not cause errors when attempting to create diagnostics
        if (
          this.targetDocument &&
          (vulnLine < 0 || vulnLine >= this.targetDocument.lineCount)
        ) {
          debugMessage(DebugTypes.error, `Invalid line number: ${vulnLine}`);
          return;
        }

        const url =
          "https://cwe.mitre.org/data/definitions/" +
          cweID.substring(4) +
          ".html";

        const lines = this.targetDocument?.getText().split("\n") ?? [];

        let line = this.targetDocument?.lineAt(vulnLine);

        let diagMessage = "";

        cweDescription = this.predictions.cwe.descriptions[vulCount];

        const separator = " | ";

        // diagMessage = "Line: " + (vulnLine+1) + " | CWE: " + cweID.substring(4) + " " + ((cweName === undefined || "") ? "" : ("(" + cweName + ") ") )  + "| Type: " + cweType;
        diagMessage =
          "Line " +
          (vulnLine + 1) +
          " may be vulnerable with " +
          cweID +
          " (" +
          cweName +
          " | Abstract Type: " +
          cweType +
          ")";

        const range = new vscode.Range(
          vulnLine,
          this.targetDocument?.lineAt(vulnLine)
            .firstNonWhitespaceCharacterIndex ?? 0,
          vulnLine,
          line?.text.length ?? 0,
        );

        const diagnostic = new vscode.Diagnostic(
          range,
          diagMessage,
          vscode.DiagnosticSeverity.Error,
        );

        diagnostic.code = {
          value: "More Details",
          target: vscode.Uri.parse(url),
        };

        // Pass function name to source param
        diagnostic.source = functionName;

        diagnostics.push(diagnostic);

        // Increase vulCount only if batch_vul_pred with class `1`, which means only take vulnerable function as account
        vulCount++;
      }
    });
    diagnosticCollection.delete(this.targetDocument.uri);
    diagnosticCollection.set(this.targetDocument.uri, diagnostics);
    return 0;
  }

  // Populates sidebar after inference completed
  async updateSidebarContent() {
    let vulnerabilities: VulnerabilityType[] = [];
    let vulCount = 0;

    // Check if current function is ignored
    this.functionsList.range.forEach((value: any, i: number) => {
      const functionName =
        this.functionsList.functions[i].split("(")[0].split(" ").pop() || "";
      const ignoredFunctionNames = this.targetDocument?.fileName
        ? this.fileIgnoreFunctions[this.targetDocument.fileName] || []
        : [];
      const isIgnored = ignoredFunctionNames.includes(functionName);

      // Create vulnerability type for all vulnerable functions
      if (this.predictions.line.batch_vul_pred[i] === 1) {
        const cweID = this.predictions.cwe.cwe_id[vulCount];
        const cweName = this.predictions.cwe.names[vulCount];

        const lineScores = this.predictions.line.batch_line_scores[i];
        let lineScoreShiftMapped: number[][] = [];

        this.functionsList.shift[i].forEach((element: number) => {
          lineScores.splice(element, 0, 0);
        });

        let lineStart = this.functionsList.range[i].start.line;

        lineScores.forEach((element: number, index: number) => {
          const lineNumber = lineStart + index;
          if (
            this.targetDocument &&
            lineNumber >= 0 &&
            lineNumber < this.targetDocument.lineCount
          ) {
            lineScoreShiftMapped.push([lineNumber, element]);
          }
        });

        // Sort by prediction score
        lineScoreShiftMapped.sort((a: number[], b: number[]) => {
          return b[1] - a[1];
        });

        const vulnLine = lineScoreShiftMapped[0][0];
        // ensure that invalid line numbers do not cause errors when attempting to create diagnostics
        if (
          this.targetDocument &&
          (vulnLine < 0 || vulnLine >= this.targetDocument.lineCount)
        ) {
          debugMessage(DebugTypes.error, `Invalid line number: ${vulnLine}`);
          return;
        }

        const vulnerability = {
          functionName: functionName ?? "Unknown Function", // Function name
          line: vulnLine + 1, // Line number
          title: cweName || "Detected Vulnerability", // CWE title
          description:
            this.predictions.cwe.descriptions[vulCount] || "No CWE Description", // CWE description
          cweId: cweID || "No CWE ID", // CWE ID
          generatedDesc:
            this.predictions.desc[vulCount] ||
            "No Generated Description Available", // Generated description from model
          ignored: isIgnored ? true : false,
        };

        vulnerabilities.push(vulnerability);

        vulCount++;
      }
    });

    if (this.targetDocument) {
      this.updateVulnerabilitiesPanel(this.targetDocument.uri, vulnerabilities);
    }
  }

  // Function to update the VulnerabilitiesPanel with current file's vulnerabilities
  updateVulnerabilitiesPanel(
    uri: vscode.Uri,
    vulnerabilities: VulnerabilityType[],
  ) {
    const vulnerableFile: VulnerableFileType = {
      name: path.basename(uri.fsPath),
      vulnerabilities: vulnerabilities,
    };
    VulnerabilitiesPanel.updateVulnerableFile(vulnerableFile);
  }

  removeComments(text: string): string {
    let cleanText = text;
    let newline = "\n";

    // For Block Comments (/* */)
    let pattern = /\/\*[^]*?\*\//g;
    let matches = text.matchAll(pattern);

    for (const match of matches) {
      var start = match.index ? match.index : 0; // Starting index of the match
      let length = match.length + match[0].length - 1; // Length of the match
      let end = start + length; // Ending index of the match

      let lineStart = text.substring(0, match.index).split("\n").length;
      let lineEnd = text.substring(0, end).split("\n").length;
      let diff = lineEnd - lineStart;

      cleanText = cleanText.replace(match[0], newline.repeat(diff));
    }

    // For line comments (//)
    pattern = /\/\/.*/g;
    matches = text.matchAll(pattern);
    for (const match of matches) {
      var start = match.index ? match.index : 0; // Starting index of the match
      let length = match.length + match[0].length - 1; // Length of the match
      let end = start + length; // Ending index of the match

      let lineStart = text.substring(0, match.index).split("\n").length;
      let lineEnd = text.substring(0, end).split("\n").length;
      let diff = lineEnd - lineStart;

      cleanText = cleanText.replace(match[0], newline.repeat(diff));
    }

    return cleanText;
  }

  removeBlankLines(text: string): [string, number[]] {
    let lines = text.split("\n");
    let newLines = [];
    let shiftMap = [];
    for (let i = 0; i < lines.length; i++) {
      if (!lines[i].replace(/^\s+/g, "").length) {
        // If line is empty, remove and record the line affected
        shiftMap.push(i);
      } else {
        newLines.push(lines[i]);
      }
    }
    return [newLines.join("\n"), shiftMap];
  }

  /**
   * Takes a list of CWE Types and CWE IDs and fetches the CWE data from the CWE xml
   * It stores the name and description into new fields in object: predictions.cwe.names and predictions.cwe.descriptions
   * @param list List of CWE IDs ( [[CWE Type, CWE ID]] )
   * @returns Promise that resolves when successfully retrieved CWE data from XML, rejects otherwise
   */
  async fetchCWEData(list: any) {
    try {
      // Parse cwe xml file
      const data = await fsa.readFile(cweXMLFile);
      debugMessage(DebugTypes.info, "CWE XML file read");

      try {
        debugMessage(DebugTypes.info, "Parsing CWE XML file");

        const parsed: any = await new Promise((resolve, reject) =>
          parser.parseString(data, (err: any, result: any) => {
            if (err) {
              reject(err);
              return Promise.reject(err);
            } else {
              resolve(result);
            }
          }),
        );

        if (!parsed) {
          debugMessage(DebugTypes.error, "Error parsing CWE XML file");
          return Promise.reject();
        } else {
          // Create arrays to store vulnerability names and descriptions
          debugMessage(DebugTypes.info, "Parsed CWE XML file. Getting data");
          const weaknessDescriptions: any[] = [];
          const weaknessNames: any[] = [];

          list.forEach((element: any, i: number) => {
            let weakness: any;
            let weaknessDescription: string = "";
            let weaknessName: string = "";

            // Find the weakness by ID in all possible sections
            weakness =
              parsed.Weakness_Catalog.Weaknesses[0].Weakness.find(
                (obj: any) => {
                  return obj.$.ID === element[1].toString();
                },
              ) ||
              parsed.Weakness_Catalog.Categories[0].Category.find(
                (obj: any) => {
                  return obj.$.ID === element[1].toString();
                },
              );

            if (weakness) {
              weaknessDescription =
                weakness?.Description?.[0] || weakness?.Summary?.[0] || "";
              weaknessName = weakness?.$.Name || "";
            } else {
              // Handle the case where the weakness is not found or is deprecated
              weaknessDescription =
                "This vulnerability has been deprecated or is not found.";
              weaknessName = "Deprecated or Unknown vulnerability";
            }

            weaknessDescriptions.push(weaknessDescription);
            weaknessNames.push(weaknessName);
          });

          this.predictions.cwe.descriptions = weaknessDescriptions;
          this.predictions.cwe.names = weaknessNames;

          return Promise.resolve();
        }
      } catch (err) {
        debugMessage(DebugTypes.error, "Error Parsing CWE XML file");
        return Promise.reject(err);
      }
    } catch (err: any) {
      debugMessage(
        DebugTypes.error,
        "Error while reading CWE XML file: " + err,
      );
      return Promise.reject(err);
    }
  }
}
