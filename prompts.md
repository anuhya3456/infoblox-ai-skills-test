# Prompts and iterations

This implementation is **deterministic (rules-first)** and does not require calling an external LLM to reproduce outputs. However, LLM integration can enhance accuracy for ambiguous cases.

If you choose to extend it with an LLM (recommended for ambiguous `device_type` / `owner_team`), keep:
- temperature <= 0.2
- output strictly JSON
- prompts + responses appended here

## Example prompt (not executed)
**Goal:** classify device_type from weak signals.

**Prompt**
```json
{
  "task": "Classify device_type for a network inventory record",
  "inputs": {
    "hostname": "host-02",
    "notes": "edge gw?",
    "ip": "10.0.1.300",
    "site": "HQ Bldg 1",
    "owner": "ops"
  },
  "allowed_device_types": ["router", "switch", "server", "printer", "iot", "unknown"],
  "output_schema": {
    "device_type": "string",
    "confidence": "number (0..1)",
    "rationale": "short string"
  }
}
```

**Expected JSON response shape**
```json
{"device_type":"router","confidence":0.6,"rationale":"Notes mention edge gateway (gw)."}
```

## Additional LLM Integration Examples

### Device Type Classification for Ambiguous Cases

**Scenario:** Row 2 has hostname "host-02" and notes "edge gw?" but low confidence (0.6)

**Enhanced Prompt:**
```json
{
  "task": "Refine device_type classification for network inventory",
  "context": "We are cleaning network inventory data for IPAM/DNS workflows. Device types should be one of: router, switch, server, printer, iot, unknown.",
  "inputs": {
    "hostname": "host-02",
    "notes": "edge gw?",
    "ip": "10.0.1.300",
    "site": "HQ Bldg 1", 
    "owner": "ops",
    "current_classification": "router",
    "current_confidence": 0.6
  },
  "rules_applied": "Inferred 'router' from notes containing 'edge gw?'",
  "output_schema": {
    "device_type": "string",
    "confidence": "number (0..1)",
    "rationale": "string explaining reasoning",
    "suggested_rules": "array of new rules to add to deterministic logic"
  }
}
```

### Owner Team Disambiguation

**Scenario:** Owner field contains ambiguous text like "john doe" or "team lead"

**Prompt:**
```json
{
  "task": "Extract and normalize owner information from free text",
  "context": "Parse owner field to extract name, email, and team. Teams include: ops, platform, sec, facilities.",
  "inputs": {
    "owner_raw": "john doe (network team) john.doe@corp.example.com",
    "site": "HQ Bldg 1"
  },
  "output_schema": {
    "owner_name": "string or null",
    "owner_email": "string or null", 
    "owner_team": "string or null",
    "confidence": "number (0..1)",
    "rationale": "string"
  }
}
```

### Site Normalization Enhancement

**Scenario:** Unrecognized site names that don't match existing mappings

**Prompt:**
```json
{
  "task": "Normalize site names to canonical codes",
  "context": "Map site names to canonical codes. Known codes: hq, blr-campus, lab-1, dc-1. Create new codes if needed.",
  "inputs": {
    "site_raw": "Remote Office - Seattle",
    "ip_range": "192.168.100.0/24",
    "device_count": 15
  },
  "output_schema": {
    "site_normalized": "string",
    "confidence": "number (0..1)",
    "rationale": "string",
    "suggested_mapping": "object showing raw -> normalized mapping"
  }
}
```

## Integration Points in run.py

The following functions in `run.py` are ideal candidates for LLM enhancement:

1. **`infer_device_type()`** (line 198): Add LLM fallback when confidence < 0.7
2. **`parse_owner()`** (line 160): Use LLM for complex owner strings
3. **`normalize_site()`** (line 223): LLM for unrecognized site patterns

## Implementation Suggestion

```python
import openai  # or other LLM client

def llm_classify_device_type(hostname, notes, device_type_value):
    if device_type_value and confidence >= 0.7:
        return device_type_value, confidence, ["existing_high_confidence"]
    
    prompt = {
        "task": "Classify device_type",
        "inputs": {
            "hostname": hostname,
            "notes": notes,
            "device_type_value": device_type_value
        }
    }
    
    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "system", "content": "You are a network inventory expert."},
                  {"role": "user", "content": json.dumps(prompt)}],
        temperature=0.1
    )
    
    result = json.loads(response.choices[0].message.content)
    return result["device_type"], result["confidence"], ["llm_enhanced"]
```

## Cost and Performance Considerations

- **Batch processing**: Group similar ambiguous cases for single LLM call
- **Caching**: Store LLM responses for similar patterns
- **Fallback**: Always maintain deterministic rules as baseline
- **Temperature**: Keep ≤ 0.2 for consistent outputs
