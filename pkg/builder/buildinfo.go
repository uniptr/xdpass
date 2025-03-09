package builder

import (
	"fmt"
	"os"
	"runtime"
)

var (
	Version   = "unknown"
	Commit    = "unknown"
	Date      = "unknown"
	GoVersion = runtime.Version()
)

func BuildInfo() string {
	return fmt.Sprintf("%s %s (%s %s) %s", os.Args[0], Version, Commit, Date, GoVersion)
}
