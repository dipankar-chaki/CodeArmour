// This script will be run within the webview itself
// It cannot access the main VS Code APIs directly.

(function () {
  const vscode = acquireVsCodeApi();
  let iconUriClose = "";
  let iconUriOpen = "";
  let iconUriFound = "";
  let iconUriNotFound = "";

  function renderVulnerabilities(file) {
    const filenameContainer = document.getElementById("vulnerabilitiesFilename");
    const vulnerabilitiesFound = file.vulnerabilities.length > 0;
    const vulnerabilitiesFoundMessage = vulnerabilitiesFound
      ? `${file.vulnerabilities.length} vulnerabilities found.`
      : "No vulnerabilities found.";

    const iconUri = vulnerabilitiesFound ? iconUriFound : iconUriNotFound;

    filenameContainer.innerHTML = `
      <h2>${file.name}</h2>
      <p class="vulnerabilitiesFound">
        <img src="${iconUri}" class="status-icon">
        ${vulnerabilitiesFoundMessage}
      </p>`;

    const vulnerabilitiesContainer = document.getElementById("vulnerabilities");
    vulnerabilitiesContainer.innerHTML = file.vulnerabilities
      .map(
        (vulnerability, index) => `
        <div class="vulnerabilityItemContainer">
          <details class="vulnerabilityContainer">
            <summary class="vulnerabilityTitle">
              Function: ${vulnerability.functionName} | Line: ${vulnerability.line} | ${vulnerability.title}
              <span class="expand-icon"></span>
            </summary>
            <div class="vulnerabilityContent">
              <p><span class="sidebar-content-title">CWE-ID: </span>${vulnerability.cweId}<p>
              <p class="line-gap"><span class="sidebar-content-title">Generated Description: </span>${vulnerability.generatedDesc}</p>
            </div>
          </details>
          <img src="${vulnerability.ignored ? iconUriClose : iconUriOpen}" class="ignore-icon" data-index="${index}">
        </div>
      `
      )
      .join("");

    document.querySelectorAll(".ignore-icon").forEach((element) => {
      element.addEventListener("click", (event) => {
        const functionIndex = event.target.getAttribute("data-index");
        vscode.postMessage({
          command: "ignoreFunction",
          functionName: file.vulnerabilities[functionIndex].functionName,
        });
        // Toggle the icon source
        const currentSrc = event.target.getAttribute("src");
        event.target.setAttribute("src", currentSrc === iconUriClose ? iconUriOpen : iconUriClose);
      });
    });
  }

  // Handle messages sent from the extension to the webview
  window.addEventListener("message", (event) => {
    const message = event.data;
    switch (message.command) {
      case "updateVulnerabilities":
        renderVulnerabilities(message.content);
        break;
      case "setIconUri":
        iconUriClose = message.iconUriClose;
        iconUriOpen = message.iconUriOpen;
        iconUriFound = message.iconUriFound;
        iconUriNotFound = message.iconUriNotFound;
        break;
    }
  });
})();
