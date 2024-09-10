import * as vscode from "vscode";
import * as path from "path";
import { getNonce } from "./getNonce";
import { VulnerableFileType } from "./vulnerabilitiesPanel.models";
import { DebugTypes, debugMessage } from "./VulDiagnostic.model";
import { currentVulDiagnostic } from "./extension";

export class VulnerabilitiesPanel {
  /**
   * Track the currently panel. Only allow a single panel to exist at a time.
   */
  public static currentPanel: VulnerabilitiesPanel | undefined;

  public static readonly viewType = "vulnerabilities";

  private readonly _extensionUri: vscode.Uri;
  private _disposables: vscode.Disposable[] = [];
  private readonly _panel: vscode.WebviewPanel;
  private static _currentFile: VulnerableFileType = {
    name: "",
    vulnerabilities: [],
  }; // Default initialization

  // Shows panel if it exists, otherwise create one
  public static createOrShow(extensionUri: vscode.Uri) {
    const column = vscode.ViewColumn.Beside;

    // If we already have a panel, show it.
    if (VulnerabilitiesPanel.currentPanel) {
      VulnerabilitiesPanel.currentPanel._panel.reveal(column);
      VulnerabilitiesPanel.currentPanel._panel.webview.postMessage({
        command: "updateVulnerabilities",
        content: VulnerabilitiesPanel._currentFile,
      });
      return;
    }

    // Otherwise, create a new panel.
    const panel = vscode.window.createWebviewPanel(
      VulnerabilitiesPanel.viewType,
      "Code Armour",
      column,
      {
        // Enable javascript in the webview
        enableScripts: true,

        // And restrict the webview to only loading content from our extension's `media` directory.
        localResourceRoots: [vscode.Uri.joinPath(extensionUri, "media")],
      },
    );

    VulnerabilitiesPanel.currentPanel = new VulnerabilitiesPanel(
      panel,
      extensionUri,
    );
  }

  private constructor(panel: vscode.WebviewPanel, extensionUri: vscode.Uri) {
    this._panel = panel;
    this._extensionUri = extensionUri;

    // Set the webview's initial html content
    this._update();

    // Listen for when the panel is disposed
    // This happens when the user closes the panel or when the panel is closed programmatically
    this._panel.onDidDispose(() => this.dispose(), null, this._disposables);
  }

  public dispose() {
    VulnerabilitiesPanel.currentPanel = undefined;

    // Clean up our resources
    this._panel.dispose();

    while (this._disposables.length) {
      const x = this._disposables.pop();
      if (x) {
        x.dispose();
      }
    }
  }

  private _update() {
    const webview = this._panel.webview;
    this._panel.webview.html = this._getHtmlForWebview(webview);

    // Send the iconUri to the webview
    const iconUriClose = webview.asWebviewUri(
      vscode.Uri.joinPath(this._extensionUri, "media", "eye-close.svg"),
    );
    const iconUriOpen = webview.asWebviewUri(
      vscode.Uri.joinPath(this._extensionUri, "media", "eye.svg"),
    );
    const iconUriFound = webview.asWebviewUri(
      vscode.Uri.joinPath(this._extensionUri, "media", "close.svg"),
    );
    const iconUriNotFound = webview.asWebviewUri(
      vscode.Uri.joinPath(this._extensionUri, "media", "check.svg"),
    );
    webview.postMessage({
      command: "setIconUri",
      iconUriClose: iconUriClose.toString(),
      iconUriOpen: iconUriOpen.toString(),
      iconUriFound: iconUriFound.toString(),
      iconUriNotFound: iconUriNotFound.toString(),
    });

    this._panel.webview.postMessage({
      command: "updateVulnerabilities",
      content: VulnerabilitiesPanel._currentFile,
    });

    this._panel.webview.onDidReceiveMessage(
      (message) => {
        switch (message.command) {
          case "ignoreFunction":
            if (currentVulDiagnostic) {
              const functionName = message.functionName;
              const fileName = currentVulDiagnostic.targetDocument?.fileName;
              if (fileName) {
                const ignoredFunctionNames =
                  currentVulDiagnostic.fileIgnoreFunctions[fileName] || [];
                const functionIndex =
                  ignoredFunctionNames.indexOf(functionName);

                if (functionIndex === -1) {
                  // Add function name to ignoredFunctionNames if not already present
                  ignoredFunctionNames.push(functionName);
                } else {
                  // Remove function name from ignoredFunctionNames if already present
                  ignoredFunctionNames.splice(functionIndex, 1);
                }

                currentVulDiagnostic.fileIgnoreFunctions[fileName] =
                  ignoredFunctionNames;
                debugMessage(
                  DebugTypes.info,
                  `Updated ignoredFunctionNames: ${ignoredFunctionNames}`,
                );

                // Update the ignored state in the current file object
                if (VulnerabilitiesPanel._currentFile) {
                  VulnerabilitiesPanel._currentFile.vulnerabilities.forEach(
                    (vulnerability) => {
                      if (vulnerability.functionName === functionName) {
                        vulnerability.ignored = !vulnerability.ignored;
                      }
                    },
                  );
                }

                vscode.commands.executeCommand("extension.refreshDiagnostics");
              }
            }
            break;
        }
      },
      undefined,
      this._disposables,
    );

    this._updateIcon();
  }

  private _getHtmlForWebview(webview: vscode.Webview) {
    const scriptPathOnDisk = vscode.Uri.joinPath(
      this._extensionUri,
      "media",
      "main.js",
    );
    const scriptUri = webview.asWebviewUri(scriptPathOnDisk);
    const stylesPathMainPath = vscode.Uri.joinPath(
      this._extensionUri,
      "media",
      "vscode.css",
    );
    const stylesMainUri = webview.asWebviewUri(stylesPathMainPath);

    // Use a nonce to only allow specific scripts to be run
    const nonce = getNonce();

    return `<!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <!--
					Use a content security policy to only allow loading images from https or from our extension directory,
					and only allow scripts that have a specific nonce.
				-->
        <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${webview.cspSource}; img-src ${webview.cspSource} https:; script-src 'nonce-${nonce}';">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link href="${stylesMainUri}" rel="stylesheet">
        <title>Code Armour</title>
      </head>
      <body>
        <h1>Detected Vulnerabilities</h1>
        <div id="vulnerabilitiesFilename"></div>
        <div id="vulnerabilities"></div>
        <script src="${scriptUri}" nonce="${nonce}"></script>
      </body>
      </html>`;
  }

  public static updateVulnerableFile(vulnerableFile: VulnerableFileType): void {
    VulnerabilitiesPanel._currentFile = vulnerableFile;
    if (VulnerabilitiesPanel.currentPanel) {
      VulnerabilitiesPanel.currentPanel._panel.webview.postMessage({
        command: "updateVulnerabilities",
        content: VulnerabilitiesPanel._currentFile,
      });
      VulnerabilitiesPanel.currentPanel._updateIcon();
    }
  }

  private _updateIcon() {
    if (!VulnerabilitiesPanel._currentFile) {
      return;
    }

    const iconPath = vscode.Uri.joinPath(
      this._extensionUri,
      "media",
      "target.svg",
    );

    // Update the webview panel title icon
    this._panel.iconPath = {
      light: iconPath,
      dark: iconPath,
    };
  }
}
