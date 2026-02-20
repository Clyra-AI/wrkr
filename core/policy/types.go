package policy

// Rule is the deterministic policy contract loaded from YAML.
type Rule struct {
	ID          string `yaml:"id"`
	Title       string `yaml:"title"`
	Severity    string `yaml:"severity"`
	Remediation string `yaml:"remediation"`
	Kind        string `yaml:"kind"`
	Version     int    `yaml:"version"`
}

type RulePack struct {
	Rules []Rule `yaml:"rules"`
}
