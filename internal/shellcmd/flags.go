package shellcmd

import (
    "fmt"
    "strings"
)

// Parse splits argv into positional arguments and named command parameters.
// Parameters use command syntax rather than executable-style flags:
//
//   xfer send file "photo.png" to <peer>
//   xfer recv ticket <ticket> out "photo.png"
//   xfer send file photo.png to <peer> json
//
// A parameter with a value consumes the following word. Boolean parameters
// are enabled by their bare name. Parameter names come from the command's
// declared Flag specs; the Flag type is retained as internal metadata so
// handlers and completion share one schema.
func Parse(argv []string, spec []Flag) (positional []string, values map[string]string, err error) {
    byName := map[string]Flag{}
    values = map[string]string{}

    for _, f := range spec {
        byName[f.Name] = f
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
                return fmt.Errorf("parameter %s wants true/false, got %q", name, value)
            }
            values[name] = lower
            return nil
        }
        values[name] = value
        return nil
    }

    for i := 0; i < len(argv); i++ {
        w := argv[i]
        if f, ok := byName[w]; ok {
            if f.IsBool {
                values[f.Name] = "true"
                continue
            }
            if i+1 >= len(argv) {
                return nil, nil, fmt.Errorf("parameter %s needs a value", f.Name)
            }
            i++
            if err := set(f.Name, argv[i], f); err != nil {
                return nil, nil, err
            }
            continue
        }

        // Dashes are deliberately not a second syntax. This is an interactive
        // command shell, not a program pretending to be an argv parser.
        if strings.HasPrefix(w, "-") {
            return nil, nil, fmt.Errorf("unknown command parameter %q; use `%s <value>` syntax", w, strings.TrimLeft(w, "-"))
        }

        positional = append(positional, w)
    }

    var missing []string
    for _, f := range spec {
        if f.Required && values[f.Name] == "" {
            missing = append(missing, f.Name)
        }
    }
    if len(missing) > 0 {
        return nil, nil, fmt.Errorf("missing required parameter(s): %s", strings.Join(missing, ", "))
    }
    return positional, values, nil
}
