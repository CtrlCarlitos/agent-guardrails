package genconfig

// AntigravityConfig emits the proven named-wrapper shape from takumi-dream's
// working hooks.json: events live inside a "guardrail" key with "enabled"
// alongside. Antigravity has no declarative permission layer, so there is no
// permissions key.
func AntigravityConfig(binary string) Fragment {
	preCmd := binary + " hook antigravity pre"
	postCmd := binary + " hook antigravity post"
	return Fragment{
		"guardrail": map[string]any{
			"enabled": true,
			"PreToolUse": []any{
				map[string]any{
					"id":      "guardrail-antigravity-pre",
					"matcher": "run_command|view_file|write_to_file|replace_file_content|multi_replace_file_content",
					"hooks": []any{
						map[string]any{"type": "command", "command": preCmd, "timeout": 15},
					},
				},
			},
			"PostToolUse": []any{
				map[string]any{
					"id":      "guardrail-antigravity-post",
					"matcher": "write_to_file|replace_file_content|multi_replace_file_content",
					"hooks": []any{
						map[string]any{"type": "command", "command": postCmd, "timeout": 120},
					},
				},
			},
		},
	}
}
