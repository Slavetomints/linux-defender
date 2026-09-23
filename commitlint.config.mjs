// Conventional Commits, with the scopes this repo actually uses.
//
//   feat(backups): add restore from manifest
//   fix(cron): stop corrupting crontabs on write-back
//   chore(ci): pin actionlint to a release container
export default {
  extends: ["@commitlint/config-conventional"],
  rules: {
    "scope-enum": [
      1,
      "always",
      [
        "anti-persistence",
        "backups",
        "monitoring",
        "system-hardening",
        "core",
        "cli",
        "ci",
        "docs",
        "deps",
        "tests",
      ],
    ],
    // Subject wording is a style preference, not something worth failing a
    // build over; keep it as a warning.
    "subject-case": [1, "never", ["upper-case", "pascal-case", "start-case"]],
    "body-max-line-length": [1, "always", 100],
  },
};
