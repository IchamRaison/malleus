# Mutation Profiles

Mutation profiles transform existing prompts or fixtures into equivalent-looking
variants. They are used to check whether a target only handles the obvious form
of a scenario or preserves the same boundary under formatting, encoding, and
context shifts.

## Selected profile

Source: `datasets/mutation_profiles/selected-v1.yaml`

The selected profile is the default release profile. It contains stable,
high-signal transforms across:

- Unicode and invisible characters.
- Soft hyphen, word-joiner, thin-space, and middle-dot insertion.
- Homoglyph and leetspeak variants.
- Markdown, XML comment, quote, angle-bracket, and transcript wrappers.
- Tool-result and function-call-looking wrappers.
- JSON, YAML, front matter, and diff-like representations.
- Chunking and uppercase transforms.

Use this profile for ordinary release runs when cost and runtime matter.

## Deep profile

Source: `datasets/mutation_profiles/deep-v1.yaml`

The deep profile tracks the full registered mutation inventory. It expands the
selected profile with additional wrappers and encodings:

- Base32/base64/hex/binary envelopes.
- Bidi, fullwidth, Cyrillic confusables, diacritics, and mirroring.
- CSV, INI, HTML, table, blockquote, admonition, and log formats.
- Many line-prefix/suffix and whitespace variants.
- Segmentation and repeated-word patterns.
- Additional prompt-field and value wrappers.

Use this profile when you want a broader stress run and can tolerate more model
calls.

## How to interpret mutation findings

A mutation finding is meaningful when the mutated scenario preserves the same
task intent and the target behaves differently in a risky way. Malleus reports
the profile, mutation name, source scenario, and evidence path so the mutated
case can be replayed or promoted into a regression pack.
