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
let profiles = [];
let activeStep = "profiles";
const announce = (message) => {
  byId("announcement").textContent = message;
};
const selectedProfile = () =>
  profiles.find((profile) => profile.ProfileName === byId("profile").value);

function renderCommand() {
  const profile = selectedProfile();
  if (!profile) return;
  byId("command-profile").textContent = profile.ProfileName;
  byId("command-text").textContent = [
    "pwsh -NoProfile -File .\\scripts\\00-Run-Profile.ps1 `",
    `  -ProfilePath .\\examples\\profiles\\${profile.ProfileName}.json \``,
    `  -RootPath . -Mode Audit -OutputFormat ${byId("output").value}` +
      (byId("whatif").checked ? " -WhatIf" : ""),
  ].join("\n");
}

function renderProfile() {
  const profile = selectedProfile();
  byId("profile-description").textContent = descriptions[profile.ProfileName];
  byId("step-count").textContent = `${profile.Steps.length} steps`;
  byId("script-list").replaceChildren(
    ...profile.Steps.map((step) => {
      const item = document.createElement("li");
      item.textContent = step.Script;
      return item;
    }),
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
    command: "Explore a sample result →",
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

function renderFindings() {
  const matches = sample.Findings.filter(
    (finding) =>
      byId("severity").value === "all" ||
      finding.Severity === byId("severity").value,
  );
  const nodes = matches.map((finding) => {
    const article = document.createElement("article");
    const severity = document.createElement("span");
    severity.textContent = finding.Severity;
    const content = document.createElement("div");
    const title = document.createElement("h3");
    title.textContent = finding.Code;
    const message = document.createElement("p");
    message.textContent = finding.Message;
    content.append(title, message);
    article.append(severity, content);
    return article;
  });
  if (!nodes.length) {
    const empty = document.createElement("p");
    empty.textContent = "No sample findings at this severity.";
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
