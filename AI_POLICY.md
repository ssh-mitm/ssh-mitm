# Generative AI / LLM Policy

We don't police whether you use LLM-based tools (Claude Code, Copilot, Codex,
Cursor, etc.) to help write your contribution. We do care about attribution,
ownership, and copyright clarity — those are non-negotiable.

## Rules

- **No LLM/AI tool may ever be listed as author or co-author of a commit.**
  No `Co-authored-by:` trailers naming an AI tool or vendor, no "Generated
  with ..." footers, nothing that implies an AI holds any authorship stake.
  This applies to every commit merged into this project, including the
  maintainers' own.

- **No unsupervised, autonomous agentic tool runs.** AI-assisted changes must
  be reviewed and approved by a human before being committed — no unattended
  agent loops that generate, commit, and push code without a human actually
  reading and understanding every change first.

- **A human owns every contribution.** Whoever submits a pull request (or
  commits directly) certifies that they hold the copyright to the change (or
  have explicit authorization to contribute it), that they understand the
  code, and that they take full responsibility for it — regardless of what
  tools helped draft it.

- **You must be able to explain and defend your changes.** "An LLM wrote it"
  is not an acceptable answer to a review question. If you can't defend a
  change, don't submit it.

- **Low-effort, unreviewed AI output ("slop") will be closed without
  discussion**, the same as any other low-quality contribution — using AI
  tools is not an exemption from the usual bar for a good PR.

## Legal

There is ongoing legal uncertainty regarding the copyright status of
LLM-generated works and their provenance. Because of this, allowing
contributions by LLMs has unpredictable consequences for the copyright
status of this project – even when leaving aside possible copyright
violations due to plagiarism.

This policy is adapted from [pip's AI policy](https://github.com/pypa/pip/blob/main/AI_POLICY.md),
itself based on the `attrs` project's policy.
