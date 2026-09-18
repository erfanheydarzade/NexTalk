package shellcmd

import (
	"fmt"
	"strings"
)

// Parse splits argv into positionals and flag values per spec.
// Supported forms: --name value, --name=value, -n value, and bare --bool.
// A lone "--" ends flag parsing; everything after it is positional.
// Unknown flags, missing values, and missing required flags are errors
// with messages that name the offending flag.
func Parse(argv []string, spec []Flag) (positional []string, values map[string]string, err error) {
	byLong := map[string]Flag{}
	byShort := map[string]Flag{}
	values = map[string]string{}
	for _, f := range spec {
		byLong[f.Name] = f
		if f.Short != "" {
			byShort[f.Short] = f
		}
		if !f.IsBool && f.Default != "" {
			values[f.Name] = f.Default
		}
		if f.IsBool {
			values[f.Name] = "false"
		}
	}

	set := func(name, value string, f Flag) error {
		if f.IsBool {
			lower := strings.ToLower(value)
			if lower != "true" && lower != "false" && lower != "1" && lower != "0" && lower != "yes" && lower != "no" {
				return fmt.Errorf("flag --%s wants true/false, got %q", name, value)
			}
			values[name] = lower
			return nil
		}
		values[name] = value
		return nil
	}

	i := 0
	onlyPositional := false
	for i < len(argv) {
		w := argv[i]
		i++
		if onlyPositional {
			positional = append(positional, w)
			continue
		}
		if w == "--" {
			onlyPositional = true
			continue
		}
		if strings.HasPrefix(w, "--") {
			body := w[2:]
			name, value, hasValue := strings.Cut(body, "=")
			f, ok := byLong[name]
			if !ok {
				return nil, nil, fmt.Errorf("unknown flag --%s", name)
			}
			if f.IsBool {
				if hasValue {
					if err := set(name, value, f); err != nil {
						return nil, nil, err
					}
				} else {
					values[name] = "true"
				}
				continue
			}
			if !hasValue {
				if i >= len(argv) {
					return nil, nil, fmt.Errorf("flag --%s needs a value", name)
				}
				value = argv[i]
				i++
			}
			if err := set(name, value, f); err != nil {
				return nil, nil, err
			}
			continue
		}
		if strings.HasPrefix(w, "-") && len(w) == 2 {
			f, ok := byShort[w[1:]]
			if !ok {
				return nil, nil, fmt.Errorf("unknown flag -%s", w[1:])
			}
			if f.IsBool {
				values[f.Name] = "true"
				continue
			}
			if i >= len(argv) {
				return nil, nil, fmt.Errorf("flag -%s needs a value", w[1:])
			}
			if err := set(f.Name, argv[i], f); err != nil {
				return nil, nil, err
			}
			i++
			continue
		}
		positional = append(positional, w)
	}

	var missing []string
	for _, f := range spec {
		if f.Required && values[f.Name] == "" {
			missing = append(missing, "--"+f.Name)
		}
	}
	if len(missing) > 0 {
		return nil, nil, fmt.Errorf("missing required flag(s): %s", strings.Join(missing, ", "))
	}
	return positional, values, nil
}
