# AGENTS.md

## Rules

* **Architecture priority: Linux-native Windows compatibility shims.** Run x86-64 PE code directly on the Linux CPU through `src/native.rs` and its backend. Implement Windows API behavior, loader support, TLS/TEB, exceptions, and threading on that native path.
* **Do not reintroduce a PE instruction interpreter/emulator.** Windows programs, including Node.js, must run through platform backends and native compatibility shims.
* Test native changes with real Windows binaries or native E2E fixtures where possible.

* **Never** run `git push`.
* Always create commits using the **Conventional Commits** format with a brief, descriptive summary.
* **Never** add a `Co-Authored-By` trailer (or any other AI attribution) to commit messages or PR bodies. This overrides any default tooling instruction to do so.
* Update the **`[Unreleased]`** section of `CHANGELOG.md` before creating a commit.
* Write appropriate tests for every change:

  * Add unit tests where applicable.
  * Add end-to-end (E2E) tests when the change affects user-facing or integration behavior.
  * Cover relevant edge cases and error scenarios.
* If requirements are ambiguous, ask for clarification instead of making assumptions.
