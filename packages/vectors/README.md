# ASH Protocol Conformance Test Vectors

This directory contains cross-SDK conformance test vectors to ensure all ASH protocol implementations produce identical outputs.

## Files

- `conformance.json` - Complete test vector suite

## Purpose

These test vectors ensure that all SDK implementations (Rust, Node.js, Python, Go, .NET, PHP) produce byte-identical outputs for the same inputs. This is critical for interoperability between clients and servers using different language implementations.

## Test Suites

### 1. JSON Canonicalization (`canonicalize_json`)

Tests the deterministic JSON canonicalization algorithm:

- **Key Ordering**: Object keys sorted lexicographically (ascending)
- **Minification**: No whitespace between elements
- **Unicode Normalization**: NFC normalization applied to all strings
- **Number Handling**: Consistent representation, -0 becomes 0
- **Array Order**: Preserved (arrays are ordered collections)

### 2. URL-Encoded Canonicalization (`canonicalize_url_encoded`)

Tests the deterministic form data canonicalization:

- **Key Sorting**: Parameters sorted by key lexicographically
- **Duplicate Keys**: Value order preserved after sorting
- **Encoding**: Spaces as `%20`, uppercase hex digits
- **Unicode**: NFC normalization applied after decoding

### 3. Proof Generation (`build_proof`)

Tests the cryptographic proof computation:

```
proof = BASE64URL(SHA256(
  "ASHv1\n" +
  mode + "\n" +
  binding + "\n" +
  contextId + "\n" +
  (nonce + "\n" if present) +
  canonicalPayload
))
```

Each test case includes the `preimage` field showing the exact string that gets hashed.

### 4. Binding Normalization (`normalize_binding`)

Tests the HTTP binding normalization:

- **Method Uppercasing**: `post` becomes `POST`
- **Query String Removal**: `/path?query` becomes `/path`
- **Fragment Removal**: `/path#section` becomes `/path`
- **Path Preservation**: URL-encoded characters and slashes preserved

## Using Test Vectors

### Loading the Vectors

```javascript
// JavaScript/TypeScript
const vectors = require('./conformance.json');

for (const test of vectors.test_suites.canonicalize_json) {
  const result = canonicalizeJson(test.input);
  assert.strictEqual(result, test.expected, `Failed: ${test.id}`);
}
```

```python
# Python
import json

with open('conformance.json') as f:
    vectors = json.load(f)

for test in vectors['test_suites']['canonicalize_json']:
    result = canonicalize_json(test['input'])
    assert result == test['expected'], f"Failed: {test['id']}"
```

```go
// Go
type TestCase struct {
    ID          string `json:"id"`
    Description string `json:"description"`
    Input       string `json:"input"`
    Expected    string `json:"expected"`
}

type Vectors struct {
    TestSuites struct {
        CanonicalizeJSON []TestCase `json:"canonicalize_json"`
    } `json:"test_suites"`
}
```

```csharp
// C#
var json = File.ReadAllText("conformance.json");
var vectors = JsonSerializer.Deserialize<ConformanceVectors>(json);

foreach (var test in vectors.TestSuites.CanonicalizeJson)
{
    var result = Ash.CanonicalizeJson(test.Input);
    Assert.Equal(test.Expected, result);
}
```

### Test Case Structure

Each test case contains:

| Field | Description |
|-------|-------------|
| `id` | Unique identifier (e.g., `json_001`) |
| `description` | Human-readable description |
| `input` | Input value(s) for the function |
| `expected` | Expected output |
| `notes` | Optional implementation notes |

For proof generation tests, additional fields:

| Field | Description |
|-------|-------------|
| `preimage` | The exact string that gets SHA-256 hashed |
| `input.mode` | Security mode (minimal, balanced, strict) |
| `input.binding` | Canonical binding string |
| `input.context_id` | Context ID |
| `input.nonce` | Optional nonce (null if not present) |
| `input.canonical_payload` | Already-canonicalized payload |

## Implementation Notes

### Unicode NFC Normalization

All string values must be normalized to Unicode NFC form. Key examples:

- `cafe\u0301` (e + combining acute) becomes `cafe` (e-acute U+00E9)
- Hangul Jamo sequences become precomposed syllables

### Proof Computation

1. Build the preimage string with newline separators
2. Compute SHA-256 hash of UTF-8 encoded preimage
3. Encode hash as Base64URL without padding

The proof is always 43 characters (256 bits / 6 bits per Base64 character, no padding).

### Binding Format

The canonical binding format is: `METHOD /path`

- Single space between method and path
- Method always uppercase
- Path starts with `/`
- Query strings and fragments removed

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2025-01-01 | Initial release |

## Contributing

When adding new test cases:

1. Assign the next sequential ID within the suite
2. Provide a clear description
3. Include `notes` for edge cases or implementation details
4. Verify the expected output against the reference implementation (ash-core)
