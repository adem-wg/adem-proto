package args

import (
	"flag"
	"log"
	"os"
	"path/filepath"
)

var SafetyWindow int64
var ThrottleTimeout int64
var EmblemPort int
var endorsementsDir string

func AddEmblemDistributionArgs() {
	flag.Int64Var(&SafetyWindow, "sfty", 600, "how long before expiry should a new emblem be generated?")
	flag.Int64Var(&ThrottleTimeout, "timeout", 600, "how long the server will wait before sending tokens to the same address twice")
	flag.IntVar(&EmblemPort, "port", 60, "port to send emblems to")
	flag.StringVar(&endorsementsDir, "end", "", "path to endorsements")
}

func LoadEndorsements() ([][]byte, error) {
	if endorsementsDir == "" {
		log.Fatal("no --end arg")
	}

	matches, err := filepath.Glob(endorsementsDir)
	if err != nil {
		log.Fatalf("cannot expand endorsements glob: %s", err)
	}

	endorsements := [][]byte{}
	for _, fpath := range matches {
		if bs, err := os.ReadFile(fpath); err != nil {
			log.Printf("could not parse file %s", fpath)
		} else {
			endorsements = append(endorsements, bs)
		}
	}

	return endorsements, nil
}
