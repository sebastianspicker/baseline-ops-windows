// Drives the documentation tour; it never executes or sends endpoint commands.
const byId = (id) => document.getElementById(id);
const steps = ["profiles", "command", "result"];
const descriptions = {
  "baseline-audit":
    "Three checks for Defender allowlists, PowerShell logging, and App Control.",
  "endpoint-health-check":
    "Ten checks spanning protection, updates, hardware, storage, networking, and identity.",
  "rapid-triage":
    "Three entry points for support-bundle parsing, event triage, and Defender health. Review required inputs in each script’s help.",
};
const sample = {
  SchemaVersion: "2.0",
  ScriptName: "27-Defender-Health-Audit.ps1",
  Mode: "Audit",
  ComputerName: "DEMO-ENDPOINT",
  TimestampUtc: "2026-01-01T12:00:00Z",
  Result: "WARN",
  Findings: [
    {
      Code: "DEF-SignaturesOutOfDate",
      Severity: "Medium",
      Message: "DefenderSignaturesOutOfDate=True.",
    },
    {
      Code: "DEF-QuickScanOld",
      Severity: "Low",
      Message: "QuickScanAge=9 days (threshold 7).",
    },
  ],
  Summary: {
    Note: "Illustrative result for the browser tour; not an endpoint capture.",
  },
  Metadata: { Demo: true },
};
const parameterNotes = {
  Json: "Writes v2 results as JSON.",
  Console: "Prints a readable summary to the console.",
  Csv: "Writes the CSV projection of v2 results.",
  None: "Returns v2 result objects to the pipeline.",
};
let profiles = [];
let activeStep = "profiles";
let copyReset;
const announce = (message) => {
  byId("announcement").textContent = message;
};
const selectedProfile = () =>
  profiles.find((profile) => profile.ProfileName === byId("profile").value);
const element = (tag, className, text) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
};
const definitions = (target, rows) => {
  byId(target).replaceChildren(
    ...rows.map(([term, detail, className]) => {
      const row = element("div", className);
      row.append(element("dt", "", term), element("dd", "", detail));
      return row;
    }),
  );
};

function renderCommand() {
  const profile = selectedProfile();
  if (!profile) return;
  const format = byId("output").value;
  const whatIf = byId("whatif").checked;
  byId("command-profile").textContent = `${profile.ProfileName}.json`;
  byId("command-text").textContent = [
    "pwsh -NoProfile -File .\\scripts\\00-Run-Profile.ps1 `",
    `  -ProfilePath .\\examples\\profiles\\${profile.ProfileName}.json \``,
    `  -RootPath . -Mode Audit -OutputFormat ${format}` +
      (whatIf ? " -WhatIf" : ""),
  ].join("\n");
  definitions("command-key", [
    ["-ProfilePath", "The profile you reviewed in step 1."],
    ["-RootPath .", "The toolkit root that contains the scripts folder."],
    [
      "-Mode Audit",
      "Reads state. Remediation needs -Mode Remediate and confirmation.",
    ],
    [`-OutputFormat ${format}`, parameterNotes[format]],
    ...(whatIf
      ? [["-WhatIf", "Previews orchestration. No capability runs; exit 2."]]
      : []),
  ]);
}

function renderStep(step) {
  const item = element("li");
  const match = /^(\d{2})-(.+?)(\.ps1)?$/.exec(step.Script);
  const number = element("span", "cap-number", match ? match[1] : "--");
  number.setAttribute("aria-hidden", "true");
  const file = element("span", "cap-file");
  if (match) {
    file.append(
      element("span", "cap-prefix", `${match[1]}-`),
      match[2],
      element("span", "cap-ext", match[3] || ""),
    );
  } else file.textContent = step.Script;
  const notes = [
    step.ContinueOnError ? "continues on error" : "stops the run on error",
    step.Args.length
      ? `${step.Args.length} argument${step.Args.length === 1 ? "" : "s"}`
      : "no arguments",
  ];
  if (step.DependsOn?.length) notes.push(`after ${step.DependsOn.join(", ")}`);
  const body = element("span", "cap-body");
  body.append(file, element("span", "cap-notes", notes.join(", ")));
  item.append(number, body);
  return item;
}

function renderProfile() {
  const profile = selectedProfile();
  const integrity = profile.Integrity || {};
  const hashes = Object.keys(integrity.ExpectedHashes || {}).length;
  const withArgs = profile.Steps.filter((step) => step.Args.length).length;
  byId("profile-description").textContent = descriptions[profile.ProfileName];
  definitions("profile-meta", [
    ["Mode", profile.Defaults?.Mode || "Audit"],
    ["Steps with arguments", withArgs ? String(withArgs) : "None"],
    ["Signature required", integrity.RequireSigned ? "Yes" : "No"],
    ["Pinned hashes", hashes ? String(hashes) : "None"],
  ]);
  byId("profile-meta").hidden = false;
  byId("integrity-notice").hidden = Boolean(integrity.RequireSigned || hashes);
  byId("step-count").textContent = `${profile.Steps.length} steps`;
  byId("script-list").replaceChildren(
    ...profile.Steps.map((step) => renderStep(step)),
  );
  byId("profile-json").textContent = JSON.stringify(profile, null, 2);
  renderCommand();
}

function showStep(step, focus = false) {
  activeStep = step;
  for (const name of steps) byId(name).hidden = name !== step;
  for (const button of document.querySelectorAll("[data-step]")) {
    if (button.dataset.step === step)
      button.setAttribute("aria-current", "step");
    else button.removeAttribute("aria-current");
  }
  byId("next-step").textContent = {
    profiles: "Prepare an audit →",
    command: "Read a sample result →",
    result: "Back to profiles →",
  }[step];
  announce("");
  if (focus) {
    const heading = byId(`${step}-title`);
    heading.tabIndex = -1;
    heading.focus({ preventScroll: true });
    byId("workspace").scrollIntoView({ block: "start" });
  }
}

function renderSummary() {
  definitions("result-summary", [
    ["Capability", sample.ScriptName],
    ["Computer", sample.ComputerName],
    ["Mode", sample.Mode],
    ["Recorded", sample.TimestampUtc.replace("T", " ").replace("Z", " UTC")],
    ["Findings", `${sample.Findings.length} to review`],
  ]);
}

function renderFindings() {
  const matches = sample.Findings.filter(
    (finding) =>
      byId("severity").value === "all" ||
      finding.Severity === byId("severity").value,
  );
  const nodes = matches.map((finding) => {
    const article = element("article");
    article.dataset.severity = finding.Severity;
    const content = element("div");
    content.append(
      element("h4", "", finding.Code),
      element("p", "", finding.Message),
    );
    article.append(element("span", "severity", finding.Severity), content);
    return article;
  });
  if (!nodes.length) {
    const empty = element("p", "empty");
    empty.append(
      "No sample findings at this severity.",
      element("small", "", "Choose “All severities” to see both."),
    );
    nodes.push(empty);
  }
  byId("findings").replaceChildren(...nodes);
}

for (const button of document.querySelectorAll("[data-step]")) {
  button.addEventListener("click", () => showStep(button.dataset.step));
}
byId("next-step").addEventListener("click", () =>
  showStep(steps[(steps.indexOf(activeStep) + 1) % steps.length], true),
);
byId("profile").addEventListener("change", renderProfile);
byId("output").addEventListener("change", renderCommand);
byId("whatif").addEventListener("change", renderCommand);
byId("severity").addEventListener("change", () => {
  renderFindings();
  announce(
    `Showing ${byId("severity").selectedOptions[0].textContent.toLowerCase()}.`,
  );
});
byId("copy-command").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(byId("command-text").textContent);
    announce("Command copied. Review it before running on Windows.");
    const button = byId("copy-command");
    button.textContent = "Copied";
    clearTimeout(copyReset);
    copyReset = setTimeout(() => {
      button.textContent = "Copy command";
    }, 2000);
  } catch {
    announce(
      "Clipboard access is unavailable. Select and copy the command above.",
    );
  }
});
byId("download-result").addEventListener("click", () => {
  const blob = new Blob([JSON.stringify(sample, null, 2) + "\n"], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = "baselineops-sample-result.json";
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  announce("Sample JSON downloaded. It contains fictional endpoint data.");
});
byId("result-json").textContent = JSON.stringify(sample, null, 2);
renderSummary();
renderFindings();

async function loadProfiles() {
  try {
    const response = await fetch("profiles.json");
    if (!response.ok) throw new Error("Profile request failed");
    const data = await response.json();
    if (
      !Array.isArray(data) ||
      data.length !== 3 ||
      data.some(
        (profile) =>
          !Object.hasOwn(descriptions, profile.ProfileName) ||
          !Array.isArray(profile.Steps),
      )
    ) {
      throw new Error("Unexpected profile data");
    }
    profiles = data;
    byId("profile").replaceChildren(
      ...profiles.map(
        (profile) => new Option(profile.ProfileName, profile.ProfileName),
      ),
    );
    byId("profile").disabled = false;
    byId("copy-command").disabled = false;
    renderProfile();
  } catch {
    byId("profile").replaceChildren(new Option("Profiles unavailable"));
    byId("profile-description").textContent =
      "The example profiles could not be loaded.";
    byId("command-profile").textContent = "no profile";
    const empty = element(
      "li",
      "empty-row",
      "The execution order appears once the profiles load.",
    );
    byId("script-list").replaceChildren(empty);
    byId("load-error").hidden = false;
    byId("command-text").textContent =
      "Command unavailable until the example profiles load.";
  }
}
byId("copy-command").disabled = true;
loadProfiles();

// GitHub project Pages forks link back to their own repository by default.
if (location.hostname.endsWith(".github.io")) {
  const owner = location.hostname.slice(0, -".github.io".length);
  const repository = location.pathname.split("/").filter(Boolean)[0];
  if (/^[a-z\d-]+$/i.test(owner) && /^[\w.-]+$/.test(repository || "")) {
    const root = `https://github.com/${owner}/${repository}`;
    document.querySelector("[data-repo]").href = root;
    for (const link of document.querySelectorAll("[data-doc]")) {
      link.href = `${root}/blob/HEAD/${link.dataset.doc}`;
    }
  }
}
