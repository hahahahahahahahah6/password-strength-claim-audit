# Documentation claim audit

An offline static audit compares documented capability claims with Python source patterns. Review findings before drawing conclusions.

## Install and use

```sh
python3 -m pip install .
password-strength-claim-audit audit .
python3 -m password_strength_claim_audit audit . --json
```

The optional root defaults to the current directory. Use `--verbose` for details, `--ignore PREFIX` repeatedly to exclude paths, and `--fail-on medium` to make medium findings fail. The default threshold is high. Exit status is 0 for a pass, 2 for a finding at the threshold, and 1 for usage or I/O errors. The version is available with `--version`.

## Findings

```text
documented-password-strength-claim-false
documented-no-password-strength-claim-false
```

A positive claim without production evidence is high severity, or medium when evidence occurs only in tests. A denial with production evidence is high severity. Documentation consists of the root README and Markdown files under a docs component. Fenced blocks are ignored; inline code counts. Source files under fixtures, docs, or examples are excluded; tests are assessed separately.

## Limitations

- This phrase may refer to a remote service or database policy, producing a false positive:

  ```text
  validate password strength
  ```

- This phrase may refer to a manual runbook step, producing a false positive:

  ```text
  check password strength
  ```

- This phrase may refer to a roadmap item, producing a false positive:

  ```text
  password strength
  ```

- This phrase may refer to a downstream service, producing a false positive:

  ```text
  password strength check
  ```

- This phrase may refer to a hosted page, producing a false positive:

  ```text
  password strength checker
  ```

- This phrase may refer to a mockup without scoring code, producing a false positive:

  ```text
  password strength meter
  ```

- This phrase may refer to an unrelated game or quiz, producing a false positive:

  ```text
  password score
  ```

- This phrase may refer to a theoretical discussion, producing a false positive:

  ```text
  password entropy
  ```

- This phrase may refer to a length rule alone, producing a false positive:

  ```text
  detect weak password
  ```

- This phrase may refer to authentication against a stored hash, producing a false positive:

  ```text
  check password
  ```

- This phrase may refer to advice to the reader, producing a false positive:

  ```text
  strong password
  ```

- This phrase may refer to advice to the reader, producing a false positive:

  ```text
  weak password
  ```

- This phrase may refer to a generated value without a judgement, producing a false positive:

  ```text
  password is strong
  ```

- This phrase may refer to a warning without scoring code, producing a false positive:

  ```text
  password is weak
  ```

- The scoring library route matches call shape even in code that never runs.
- An indirect variable chain can hide a library call.
- An import alone is not evidence.
- Roadmap, changelog, and TODO prose still counts as a claim.
- A denial outside the listed phrases may be missed.
- A top-level changelog outside the documentation scope is not read.
- Both legs of a paired route must occur in one module.
- Local definitions shadow route names, including wrappers.
- Dead code counts.
- Subprocess calls to external tools are not evidence.
- A generic input check alone is not evidence.
- An email validation call alone is not evidence.
- A phone number validation call alone is not evidence.
- An extraction call alone is not evidence.
- A locally defined generic name is shadowed.
- Generic aliases passed through an additional assignment may be missed.
- Exact phrases are matched, not meaning.
- Only Python source is examined.
- Runtime-only routes are invisible; code is never executed and the network is never accessed.
- A policy construction alone is not evidence.
- A statistics construction alone is not evidence.
- Binding a value to a policy alone is not evidence.
- A statistics property read alone is not evidence.
- A Django authentication call alone is not evidence.
- A hashing library call alone is not evidence.
- A generation call alone is not evidence.
- A length check alone is not evidence.
- A regular expression match alone is not evidence.

## Differentiation

This audit concerns judgements of how robust a supplied secret is. Generic input validation, authentication, password hashing, password generation, PDF encryption, email sending, SMS sending, email validation, phone number validation, JSON Schema validation, JSON decoding, document extraction, barcode and QR decoding, and regular expression matching are separate capabilities. Other families cover spreadsheet and word-document reading and generation, presentation reading and generation, PDF extraction, generation, merging, splitting, rotation, form filling, watermarking, redaction, compression and annotation, table extraction, OCR, e-signature, payment processing, screen recording, video generation, QR and barcode generation, barcode scanning, audio mixing, generation and editing, source separation, speech recognition, text-to-speech, noise suppression, music generation and transcription. Those capabilities alone do not establish evidence here.
