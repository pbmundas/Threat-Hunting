# Regex Cheat Sheet (with Examples + Real Uses)

### Basics

* `cat`
  Matches the exact word “cat”.
  **Use**: Find a specific keyword in logs or text.
  Example: `"black cat running"` → **cat**

* `.`
  Matches any single character (except newline).
  **Use**: Find variations with one unknown character.
  Example: `c.t` → **cat**, **cot**, **c9t**

---

### Character Classes

* `[abc]`
  Matches one of a, b, or c.
  **Use**: Detect variations like “gray/grey”.
  Example: `[ae]` in `gr[ae]y` → **gray**, **grey**

* `[a-z]`
  Any lowercase letter.
  **Use**: Ensure only lowercase usernames.

* `[^abc]`
  Anything except a, b, or c.
  **Use**: Exclude unwanted characters.

---

### Predefined Classes

* `\d`
  Any digit.
  **Use**: Extract numbers like IP parts, years.
  Example: `\d\d\d` → **404**

* `\w`
  Word characters (letters, numbers, `_`).
  **Use**: Match variable names in code.
  Example: `user_\w+` → **user\_id**

* `\s`
  Whitespace.
  **Use**: Split text where spaces/tabs matter.
  Example: `hello\s+world` → matches “hello   world”

---

### Quantifiers

* `a*`
  0 or more `a`s.
  **Use**: Handle optional repetitions (like trailing letters).

* `a+`
  1 or more `a`s.
  **Use**: Ensure a sequence exists at least once.

* `\d{3}`
  Exactly 3 digits.
  **Use**: Validate area codes, OTPs, short IDs.
  Example: **123**

* `\d{2,4}`
  Between 2 and 4 digits.
  **Use**: Match years (e.g., 99, 2025).

---

### Anchors

* `^Hello`
  Must start with “Hello”.
  **Use**: Ensure log lines or emails begin correctly.

* `world$`
  Must end with “world”.
  **Use**: Match file extensions, line endings.

* `\bcat\b`
  Whole word “cat”.
  **Use**: Avoid matching “catalog” when searching for “cat”.

---

### Groups & Alternation

* `(abc)`
  Captures a group.
  **Use**: Extract useful data from text.

* `(a|b)`
  Either a or b.
  **Use**: Match multiple options (color vs colour).

* `(ha)+`
  One or more “ha”.
  **Use**: Detect repeated tokens like laughter, “yesyesyes”.

---

### Escaping

* `\.`
  Match a real dot `.`.
  **Use**: Match file names (`file.txt`).

* `\\`
  Match a backslash `\`.
  **Use**: Windows paths (`C:\\Users\\`).

---

### Practical Patterns

* **Email**: `^\w+@\w+\.\w+$`
  **Use**: Validate simple emails.
  Example: **[test@mail.com](mailto:test@mail.com)**

* **Phone**: `^\d{10}$`
  **Use**: Match 10-digit phone numbers.
  Example: **9876543210**

* **Date (YYYY-MM-DD)**: `^\d{4}-\d{2}-\d{2}$`
  **Use**: Validate system log timestamps.
  Example: **2025-09-17**

* **Extract exe\_name**: `"exe_name":\s*"(.*?)"`
  **Use**: Parse JSON logs for process names.
  Example: `"exe_name":"dockerd"`

---

### Flags

* `/cat/i` → case-insensitive (Cat, cAt, CAT)
  **Use**: Ignore casing in search.

* `/cat/g` → match all occurrences
  **Use**: Replace all instances in text.

* `/^hi/m` → multiline mode
  **Use**: Match start of each line in logs.

---

**Key Takeaway:** Regex is not just “fancy search” — it’s for **validation, extraction, and transformation** across logs, configs, code, and data.

---
