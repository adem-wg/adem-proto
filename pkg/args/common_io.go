package args

import (
	"flag"
	"log"
	"os"
	"path"
	"path/filepath"
)

var SafetyWindow int
var Port int
var endorsementsDir string

func init() {
	flag.IntVar(&SafetyWindow, "sfty", 600, "how long before expiry should a new emblem be generated?")
	flag.IntVar(&Port, "port", 60, "emblem server port")
	flag.StringVar(&endorsementsDir, "end", "", "path to endorsements")
}

func LoadEndorsements() ([]string, error) {
	if endorsementsDir == "" {
		log.Fatal("no --end arg")
	}

	matches, err := filepath.Glob(endorsementsDir)
	if err != nil {
		log.Fatalf("cannot expand endorsements glob: %s", err)
	}

	endorsements := []string{}
	for _, fpath := range matches {
		switch path.Ext(fpath) {
		case ".jwt":
			bs, err := os.ReadFile(fpath)
			if err != nil {
				log.Printf("could not parse file %s", fpath)
			}
			endorsements = append(endorsements, string(bs))
		}
	}

	return endorsements, nil
}
