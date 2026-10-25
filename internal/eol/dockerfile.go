package eol

import (
	"regexp"
	"strings"
)

// dockerfilePins reads every FROM of a Dockerfile, including later stages,
// and resolves ${ARG} references from the ARG defaults declared before the
// first FROM, which are the only ones a FROM can see. A reference to an earlier
// stage, scratch, or an unresolvable argument yields no pin.
func dockerfilePins(rel string, content []byte) []Pin {
	var pins []Pin
	args := map[string]string{}
	stages := map[string]bool{}
	seenFrom := false
	for _, instruction := range instructions(content) {
		pins = append(pins, snapshotLinePins(rel, instruction.line, instruction.text)...)
		fields := strings.Fields(instruction.text)
		if len(fields) < 2 {
			continue
		}
		switch strings.ToUpper(fields[0]) {
		case "ARG":
			if seenFrom {
				continue
			}
			for _, declaration := range fields[1:] {
				name, value, _ := strings.Cut(declaration, "=")
				args[name] = strings.Trim(value, `"'`)
			}
		case "FROM":
			seenFrom = true
			var operands []string
			for _, field := range fields[1:] {
				if !strings.HasPrefix(field, "--") {
					operands = append(operands, field)
				}
			}
			if len(operands) == 0 {
				continue
			}
			reference, ok := expand(operands[0], args)
			earlierStage := ok && stages[strings.ToLower(reference)]
			if len(operands) >= 3 && strings.EqualFold(operands[1], "AS") {
				stages[strings.ToLower(operands[2])] = true
			}
			if !ok || earlierStage || strings.EqualFold(reference, "scratch") {
				continue
			}
			pins = append(pins, imagePins(reference, rel, instruction.line, "FROM")...)
		}
	}
	return pins
}

type instruction struct {
	line int
	text string
}

// instructions joins backslash continuations and drops comments; line is the
// instruction's first physical line.
func instructions(content []byte) []instruction {
	var out []instruction
	var current strings.Builder
	start := 0
	for index, raw := range lines(content) {
		trimmed := strings.TrimSpace(raw)
		if current.Len() == 0 {
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			start = index + 1
		} else if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if body, continued := strings.CutSuffix(trimmed, `\`); continued {
			current.WriteString(body)
			current.WriteString(" ")
			continue
		}
		current.WriteString(trimmed)
		out = append(out, instruction{line: start, text: current.String()})
		current.Reset()
	}
	if current.Len() > 0 {
		out = append(out, instruction{line: start, text: current.String()})
	}
	return out
}

var argReference = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-+])([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)`)

// expand substitutes $NAME, ${NAME}, ${NAME:-default} and ${NAME:+word}
// (and their forms without the colon). A reference with no value and no
// default leaves the image unresolved.
func expand(value string, args map[string]string) (string, bool) {
	resolved := true
	out := argReference.ReplaceAllStringFunc(value, func(reference string) string {
		match := argReference.FindStringSubmatch(reference)
		name, operator, word := match[1], match[2], match[3]
		if name == "" {
			name = match[4]
		}
		found, set := args[name]
		nonEmpty := set && found != ""
		switch operator {
		case ":-":
			if nonEmpty {
				return found
			}
			return word
		case "-":
			if set {
				return found
			}
			return word
		case ":+":
			if nonEmpty {
				return word
			}
			return ""
		case "+":
			if set {
				return word
			}
			return ""
		}
		if !nonEmpty {
			resolved = false
		}
		return found
	})
	return out, resolved && out != ""
}

// variantWords are image tag variants that never name a distribution release.
var variantWords = map[string]bool{"slim": true, "alpine": true, "full": true, "nonroot": true}

var imageProducts = map[string]string{
	"node": "nodejs", "golang": "go", "rust": "rust", "python": "python",
	"ubuntu": "ubuntu", "debian": "debian", "alpine": "alpine-linux", "bun": "bun",
}

var (
	alpineVariant    = regexp.MustCompile(`^alpine([0-9]+\.[0-9]+)$`)
	distrolessDebian = regexp.MustCompile(`-debian([0-9]+)$`)
	distrolessNode   = regexp.MustCompile(`^nodejs([0-9]+)-`)
	codenameToken    = regexp.MustCompile(`^[a-z]{4,}$`)
)

// imagePins maps an image reference such as
// "registry.example/mirror/library/node:22.1.0-bookworm-slim@sha256:..." to
// the products it selects: the image's own runtime or distribution from its
// repository name and leading tag version, plus a distribution named by a tag
// variant (bookworm, noble, alpine3.20) or a distroless "-debianNN" suffix.
func imagePins(reference, rel string, line int, source string) []Pin {
	reference, _, _ = strings.Cut(reference, "@")
	repository, tag := reference, ""
	if colon := strings.LastIndex(reference, ":"); colon > strings.LastIndex(reference, "/") {
		repository, tag = reference[:colon], reference[colon+1:]
	}
	name := strings.ToLower(repository[strings.LastIndex(repository, "/")+1:])
	label := source + " " + reference
	var pins []Pin
	if match := distrolessDebian.FindStringSubmatch(name); match != nil {
		pins = append(pins, pin("debian", match[1], rel, line, label))
	}
	if match := distrolessNode.FindStringSubmatch(name); match != nil {
		pins = append(pins, pin("nodejs", match[1], rel, line, label))
	}
	if tag == "" || tag == "latest" {
		return pins
	}
	tokens := strings.Split(strings.ToLower(tag), "-")
	product, known := imageProducts[name]
	if known {
		first := tokens[0]
		switch {
		case first != "" && first[0] >= '0' && first[0] <= '9':
			pins = append(pins, pin(product, first, rel, line, label))
		case (product == "debian" || product == "ubuntu") && codenameToken.MatchString(first):
			found := pin(product, first, rel, line, label)
			found.Codename = true
			pins = append(pins, found)
		}
	}
	for _, token := range tokens[1:] {
		if match := alpineVariant.FindStringSubmatch(token); match != nil {
			pins = append(pins, pin("alpine-linux", match[1], rel, line, label))
			continue
		}
		if codenameToken.MatchString(token) && !variantWords[token] {
			pins = append(pins, Pin{
				Products: []string{"debian", "ubuntu"}, Version: token, Path: rel, Line: line,
				Source: label, Codename: true,
			})
		}
	}
	return pins
}
