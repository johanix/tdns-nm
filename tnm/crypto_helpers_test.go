package tnm

import "testing"

func TestSelectBackend(t *testing.T) {
	tests := []struct {
		name      string
		supported []string
		forced    string
		want      string
		wantErr   bool
	}{
		{"empty list means jose", nil, "", "jose", false},
		{"jose", []string{"jose"}, "", "jose", false},
		{"stored hpke first is skipped", []string{"hpke", "jose"}, "", "jose", false},
		{"forced jose", []string{"hpke", "jose"}, "jose", "jose", false},
		{"forced hpke is not available", []string{"hpke", "jose"}, "hpke", "jose", false},
		{"only hpke is an error", []string{"hpke"}, "", "", true},
	}
	for _, tt := range tests {
		got, err := SelectBackend(tt.supported, tt.forced)
		if (err != nil) != tt.wantErr {
			t.Errorf("%s: SelectBackend(%v, %q) error = %v, wantErr %v", tt.name, tt.supported, tt.forced, err, tt.wantErr)
			continue
		}
		if got != tt.want {
			t.Errorf("%s: SelectBackend(%v, %q) = %q, want %q", tt.name, tt.supported, tt.forced, got, tt.want)
		}
	}
}
