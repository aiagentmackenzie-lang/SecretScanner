package output

import (
	"io"

	"github.com/aiagentmackenzie-lang/SecretScanner/pkg/scanner"
)

// Formatter defines the interface for output formatters
type Formatter interface {
	Format(report *scanner.Report, w io.Writer) error
}

// Available formatters
var Formatters = map[string]Formatter{
	"json":     &JSONFormatter{},
	"sarif":    &SARIFFormatter{},
	"csv":      &CSVFormatter{},
	"terminal": &TerminalFormatter{},
}

// GetFormatter returns a formatter by name
func GetFormatter(name string) (Formatter, bool) {
	f, ok := Formatters[name]
	return f, ok
}
