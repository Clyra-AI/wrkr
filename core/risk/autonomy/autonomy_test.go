package autonomy

import "testing"

func TestClassify(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		signal Signals
		want   string
	}{
		{name: "interactive default", signal: Signals{}, want: LevelInteractive},
		{name: "copilot override", signal: Signals{Tool: "copilot", Headless: true}, want: LevelCopilot},
		{name: "headless gated", signal: Signals{Headless: true, HasApprovalGate: true}, want: LevelHeadlessGate},
		{name: "headless auto", signal: Signals{Headless: true}, want: LevelHeadlessAuto},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := Classify(tc.signal)
			if got != tc.want {
				t.Fatalf("unexpected classification: got %s want %s", got, tc.want)
			}
		})
	}
}

func TestIsCritical(t *testing.T) {
	t.Parallel()
	if !IsCritical(Signals{Headless: true, HasSecretAccess: true, DangerousFlags: true}) {
		t.Fatal("expected critical for headless auto with secrets and dangerous flags")
	}
	if IsCritical(Signals{Headless: true, HasSecretAccess: false, DangerousFlags: true}) {
		t.Fatal("did not expect critical without secret access")
	}
}
