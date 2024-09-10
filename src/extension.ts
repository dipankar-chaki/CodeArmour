// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from "vscode";
import { VulnerabilitiesPanel } from "./vulnerabilitiesPanel";
import { DebugTypes, debugMessage } from "./VulDiagnostic.model";
import { VulDiagnostic } from "./VulDiagnostic";
import { Progress, ProgressStages, downloadEngine } from "./common";
import { promisify } from "util";
import { exec } from "child_process";

const execAsync = promisify(exec);

// modules
export const axios = require("axios");
export const fs = require("fs");
export const path = require("path");
export const fsa = require("fs/promises");
export const extract = require("extract-zip");
export const parser = require("xml2js");

const parentDir = path.resolve(__dirname, "..");
export const progressEmitter = new Progress();
let statusBarItem: vscode.StatusBarItem;
let lock = false;
const TYPE_WAIT_DELAY = 1500;
export let cweXMLFile: string = path.join(
  __dirname,
  "..",
  "resources",
  "cwec_v4.8.xml",
);
export let currentVulDiagnostic: VulDiagnostic | null = null;
export let activeFileIgnoreFunctions: { [key: string]: string[] } = {};

// This method is called when your extension is activated
// Your extension is activated the very first time the command is executed
export function activate(context: vscode.ExtensionContext) {
  debugMessage(DebugTypes.info, "Code Armour activated");
  debugMessage(DebugTypes.info, __dirname);

  // Defining a diagnostic collection
  const diagnosticCollection =
    vscode.languages.createDiagnosticCollection("Code Armour");
  context.subscriptions.push(diagnosticCollection);

  // Diagnostic queue to ignore unwanted diagnostics
  let diagnosticsQueue: VulDiagnostic[] = [];

  progressEmitter.on("init", async (stage: ProgressStages) => {
    switch (stage) {
      case ProgressStages.extensionInitStart:
        // Download models and CWE list if not found

        if (!lock) {
          lock = true;

          let hasError = true;
          while (hasError) {
            await init()
              .then(() => {
                hasError = false;
              })
              .catch((err) => {
                debugMessage(DebugTypes.error, err);
                debugMessage(
                  DebugTypes.info,
                  "Error occured during initialisation. Retrying...",
                );
              });
          }
          lock = false;
        } else {
          debugMessage(
            DebugTypes.info,
            "Extension initialisation already in progress",
          );
        }
        progressEmitter.emit("init", ProgressStages.analysisStart);
        break;
      case ProgressStages.analysisStart:
        if (!lock) {
          if (vscode.window.activeTextEditor?.document) {
            // If there are duplicate requests, only show the result of the last request
            if (diagnosticsQueue.length > 0) {
              diagnosticsQueue.forEach((element) => {
                element.ignore = true;
              });
            }
            // Creating a VulDiagnostic for current scan
            const vulDiagnostic = new VulDiagnostic(
              vscode.window.activeTextEditor?.document,
              activeFileIgnoreFunctions,
            );

            diagnosticsQueue.push(vulDiagnostic);
            currentVulDiagnostic = vulDiagnostic;

            // Performing analysis sequence within class
            await vulDiagnostic
              .analysisSequence(diagnosticCollection)
              .then(() => {
                diagnosticsQueue.forEach((item, index) => {
                  if (item === vulDiagnostic) {
                    diagnosticsQueue.splice(index, 1);
                  }
                });
              })
              .catch((err) => {
                debugMessage(DebugTypes.error, "Error occured during analysis");
                progressEmitter.emit("end", ProgressStages.error);
              });
          } else {
            debugMessage(DebugTypes.info, "No active text editor");
            progressEmitter.emit("end", ProgressStages.noDocument);
            break;
          }
        } else {
          debugMessage(DebugTypes.info, "Analysis already in progress");
        }
        break;
    }
  });

  // Define a command to show the sidebar
  context.subscriptions.push(
    vscode.commands.registerCommand("extension.showVulnerabilities", () => {
      VulnerabilitiesPanel.createOrShow(context.extensionUri);
    }),
  );

  // Add a command to refresh diagnostics after updating the ignored functions array
  context.subscriptions.push(
    vscode.commands.registerCommand(
      "extension.refreshDiagnostics",
      async () => {
        debugMessage(DebugTypes.info, "Called refreshDiagnostics");
        if (currentVulDiagnostic) {
          await currentVulDiagnostic.constructDiagnostics(diagnosticCollection);
          debugMessage(
            DebugTypes.info,
            `Current fileIgnoreFunctions: ${JSON.stringify(currentVulDiagnostic.fileIgnoreFunctions, null, 2)}`,
          );
        }
      },
    ),
  );

  // Hover menu `Open CodeAemour` button
  vscode.languages.registerHoverProvider("*", {
    provideHover(document, position) {
      const range = document.getWordRangeAtPosition(position);

      const markdownString = new vscode.MarkdownString(
        `[Open CodeArmour](command:extension.showVulnerabilities "Open CodeArmour")`,
      );
      markdownString.isTrusted = true;

      return new vscode.Hover(markdownString, range);
    },
  });

  // When text document is modified
  let pause: NodeJS.Timeout;
  vscode.workspace.onDidChangeTextDocument((e) => {
    if (e.contentChanges.length > 0) {
      clearTimeout(pause);

      pause = setTimeout(() => {
        debugMessage(
          DebugTypes.info,
          "Typing stopped for " + TYPE_WAIT_DELAY + "ms",
        );

        progressEmitter.emit("init", ProgressStages.extensionInitStart);
      }, TYPE_WAIT_DELAY);
    }
  });

  // When user changes settings
  vscode.workspace.onDidChangeConfiguration((e) => {
    debugMessage(DebugTypes.info, "Configuration Changed");
    progressEmitter.emit("init", ProgressStages.extensionInitStart);
  });

  // When user changes document
  vscode.window.onDidChangeActiveTextEditor((e) => {
    debugMessage(DebugTypes.info, "Active text editor changed");
    if (e?.document) {
      progressEmitter.emit("init", ProgressStages.extensionInitStart);
    }
  });
}

/**
 * Initialises the extension by downloading the models and CWE list if not found locally
 * Also verifies the submodule is initialized and updated, and checks the tokenizer presence
 * @returns Promise that resolves when models and CWE list are loaded, rejects if error occurs
 */
async function init() {
  const start = new Date().getTime();

  debugMessage(
    DebugTypes.info,
    "Config loaded, checking model and CWE list presence",
  );

  var downloadCandidates = [
    downloadCWEXML(),
    downloadModels(),
    downloadSubmodule(),
  ];

  await Promise.all(downloadCandidates)
    .then(() => {
      var end = new Date().getTime();
      debugMessage(
        DebugTypes.info,
        "Initialisation took " + (end - start) + "ms",
      );
      debugMessage(
        DebugTypes.info,
        "Model, CWE list and submodule successfully loaded",
      );
      return Promise.resolve();
    })
    .catch((err) => {
      debugMessage(DebugTypes.error, err);
      return Promise.reject(err);
    });
}

/**
 * Verifies and updates the submodule if necessary
 */
async function downloadSubmodule() {
  const tokenizerPath = path.join(
    __dirname,
    "..",
    "resources",
    "inference-common",
    "tokenizer",
  );

  try {
    await checkTokenizerPresence(tokenizerPath);
    debugMessage(
      DebugTypes.info,
      "Tokenizer files already present, skipping submodule update",
    );
  } catch (err) {
    debugMessage(
      DebugTypes.info,
      "Tokenizer files not found, initializing and updating submodule...",
    );

    const repoRoot = await findGitRoot(__dirname);
    if (!repoRoot) {
      throw new Error("Git repository root not found");
    }

    await execAsync("git submodule init", { cwd: repoRoot });
    await execAsync("git submodule update", { cwd: repoRoot });

    try {
      await checkTokenizerPresence(tokenizerPath);
    } catch (err) {
      debugMessage(
        DebugTypes.error,
        "Error verifying tokenizer after submodule update: " + err,
      );
      throw err;
    }
  }
  debugMessage(DebugTypes.info, "Submodule verified and tokenizer present");
}

/**
 * Finds the root of the Git repository by looking for the .git directory
 * @param dir Directory to start the search from
 * @returns Promise that resolves with the path to the Git root directory
 */
async function findGitRoot(dir: string): Promise<string | null> {
  const gitDir = path.join(dir, ".git");
  if (fs.existsSync(gitDir)) {
    return dir;
  }

  const parentDir = path.dirname(dir);
  if (parentDir === dir) {
    return null;
  }

  return findGitRoot(parentDir);
}

/**
 * Checks if the tokenizer files are present in the submodule
 * @param tokenizerPath Path to the tokenizer directory
 */
async function checkTokenizerPresence(tokenizerPath: string) {
  if (!fs.existsSync(tokenizerPath)) {
    throw new Error(`Tokenizer directory not found at ${tokenizerPath}`);
  }

  const requiredFiles = [
    "special_tokens_map.json",
    "vocab.json",
    "tokenizer_config.json",
  ];
  for (const file of requiredFiles) {
    if (!fs.existsSync(path.join(tokenizerPath, file))) {
      throw new Error(
        `Required tokenizer file ${file} not found in ${tokenizerPath}`,
      );
    }
  }

  debugMessage(DebugTypes.info, "Tokenizer files verified");
}

/**
 * Checks for presence of cwe list zip/xml file and downloads if not present
 * @returns Promise that resolves when CWE list is loaded
 */
async function downloadCWEXML() {
  const zipDownloadDir = parentDir + "/resources";
  const zipPath = path.resolve(zipDownloadDir, "cwec_latest.xml.zip");
  const extractTarget = path.resolve(zipDownloadDir);

  var files = fs
    .readdirSync(extractTarget)
    .filter((file: string) => file.endsWith(".xml"))
    .filter((file: string) => file.includes("cwec"));

  // Download if no xml file found
  if (!fs.existsSync(zipPath) || files.length === 0) {
    // If zip file doesn't exist or no xml files found
    debugMessage(
      DebugTypes.info,
      "cwec_latest.xml.zip not found, downloading...",
    );
    await downloadEngine(
      fs.createWriteStream(zipPath),
      "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
    )
      .then(() => {
        debugMessage(DebugTypes.info, "cwec_latest.xml.zip downloaded");
      })
      .catch((err) => {
        debugMessage(
          DebugTypes.error,
          "Error occured while downloading cwec_latest.xml.zip",
        );
        return Promise.reject(err);
      });
  } else if (files.length > 0) {
    // If xml file found
    debugMessage(
      DebugTypes.info,
      "xml file already exists, skipping download...",
    );
    files = fs
      .readdirSync(extractTarget)
      .filter((file: string) => file.endsWith(".xml"))
      .filter((file: string) => file.includes("cwec"));
    cweXMLFile = path.resolve(zipDownloadDir, files[0]);
    return Promise.resolve();
  }

  // Extract zip file
  debugMessage(DebugTypes.info, "Extracting cwec_latest.xml.zip");

  await extract(zipPath, { dir: extractTarget })
    .then(() => {
      debugMessage(
        DebugTypes.info,
        "cwec_latest.xml.zip extracted at " + extractTarget.toString(),
      );
      files = fs
        .readdirSync(extractTarget)
        .filter((file: string) => file.endsWith(".xml"))
        .filter((file: string) => file.includes("cwec"));
      cweXMLFile = path.resolve(zipDownloadDir, files[0]);
      return Promise.resolve();
    })
    .catch((err: any) => {
      debugMessage(
        DebugTypes.error,
        "Error occured while extracting cwec_latest.xml.zip",
      );
      return Promise.reject(err);
    });
}
/**
 * Check if the models are downloaded and download if not
 */
async function downloadModels() {
  const ModelDownloadstatusBarItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    100,
  );
  ModelDownloadstatusBarItem.text = "CodeArmour: Downloading models...";

  let modelPath = parentDir + "/resources/models";

  // Create models directory if it does not exist
  if (!fs.existsSync(path.join(modelPath))) {
    fs.mkdirSync(path.join(modelPath), { recursive: true }, (err: any) => {
      if (err) {
        return console.error(err);
      }
      debugMessage(
        DebugTypes.info,
        "Directory created successfully at " + path.join(modelPath),
      );
    });
  }

  // Model paths
  const binLineModelPath = path.resolve(modelPath, "12heads_linevul_model.bin");
  const lineModelPath = path.resolve(modelPath, "line_model.onnx");
  const cweModelPath = path.resolve(modelPath, "cwe_model.onnx");
  const descModelPath = path.resolve(
    modelPath,
    "NoEmptyRows_description_repair_train_t5.bin",
  );

  const localInferenceData = path.resolve(
    modelPath,
    "local-inference-data.zip",
  );

  var downloads = [];

  const extractTarget = path.resolve(modelPath);

  // Show status bar to indicate models are downloading
  if (
    !fs.existsSync(binLineModelPath) ||
    !fs.existsSync(cweModelPath) ||
    !fs.existsSync(descModelPath)
  ) {
    ModelDownloadstatusBarItem.show();
  }

  // Download missing models
  if (!fs.existsSync(binLineModelPath)) {
    debugMessage(DebugTypes.info, "line_model not found, downloading...");
    downloads.push(
      downloadEngine(
        fs.createWriteStream(binLineModelPath),
        "https://drive.usercontent.google.com/download?id=1vxwRjXpHaTOLsbA6byB9AEr9SJrUv1Xl&export=download&authuser=0&confirm=t&uuid=b7c161df-57ac-44bb-8e07-93d2f86771b0&at=APZUnTXA_38iiAV4T-5UvJEREYxg%3A1722346427386",
      ),
    );
  } else {
    debugMessage(
      DebugTypes.info,
      "binline_model found at " + binLineModelPath + ", skipping download...",
    );
  }

  if (!fs.existsSync(cweModelPath)) {
    debugMessage(DebugTypes.info, "cwe_model not found, downloading...");
    downloads.push(
      downloadEngine(
        fs.createWriteStream(cweModelPath),
        "https://object-store.rc.nectar.org.au/v1/AUTH_bec3bd546fd54995896239e9ff3d4c4f/AIBugHunterModels/models/cwe_model.onnx",
      ),
    );
  } else {
    debugMessage(
      DebugTypes.info,
      "cwe_model found at " + cweModelPath + ", skipping download...",
    );
  }

  if (!fs.existsSync(descModelPath)) {
    debugMessage(DebugTypes.info, "desc_model not found, downloading...");
    downloads.push(
      downloadEngine(
        fs.createWriteStream(descModelPath),
        "https://drive.usercontent.google.com/download?id=1Smy_kStaO4P0fN1Bs99l-xCxfyiPzl9U&export=download&authuser=0&confirm=t&uuid=becf0313-c0e3-41d7-a330-6820617e008d&at=APZUnTVtJ09rZtAv7EiLPJH42k0Z%3A1722347798193",
      ),
    );
  } else {
    debugMessage(
      DebugTypes.info,
      "desc_model found at " + descModelPath + ", skipping download...",
    );
  }

  // Update status bar to indicate models downloaded or error
  await Promise.all(downloads)
    .then(() => {
      debugMessage(DebugTypes.info, "Completed model initialization");
      ModelDownloadstatusBarItem.text =
        "CodeArmour: Models downloaded successfully";
      setTimeout(() => {
        ModelDownloadstatusBarItem.hide();
      }, 5000); // Hide after 5 seconds

      return Promise.resolve();
    })
    .catch((err) => {
      debugMessage(DebugTypes.error, "Error occured while downloading models");
      ModelDownloadstatusBarItem.text = "CodeArmour: Model download failed";
      vscode.window.showErrorMessage(
        "Failed to download the models: " + err.message,
      );
      setTimeout(() => {
        ModelDownloadstatusBarItem.hide();
      }, 5000); // Hide after 5 seconds
      return Promise.reject(err);
    });
}
export function deactivate() {}
