package entropy

import (
	"testing"
)

func TestCalculator_Calculate(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		minEnt   float64
		expected float64
	}{
		{
			name:     "empty string",
			data:     "",
			minEnt:   3.0,
			expected: 0,
		},
		{
			name:     "low entropy string",
			data:     "aaaaaaaa",
			minEnt:   3.0,
			expected: 0,
		},
		{
			name:     "high entropy random",
			data:     "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			minEnt:   3.0,
			expected: 4.5,
		},
		{
			name:     "github token",
			data:     "ghp_FAKE0TOKEN0FOR0TESTING0PURPOSES0ONLY",
			minEnt:   3.0,
			expected: 3.8,
		},
		{
			name:     "slack token",
			data:     "SLCK-BOT-TOKEN-FOR-ENTROPY-TEST-CASE",
			minEnt:   3.0,
			expected: 2.9,
		},
		{
			name:     "sequential hex",
			data:     "0123456789abcdef",
			minEnt:   3.0,
			expected: 2.5,
		},
		{
			name:     "all lowercase penalty",
			data:     "abcdefghijklmnopqrstuvwxyz1234567890",
			minEnt:   3.0,
			expected: 3.8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := New(tt.minEnt)
			got := c.Calculate(tt.data)

			// Allow some tolerance for entropy calculation
			tolerance := 0.5
			if got < tt.expected-tolerance || got > tt.expected+tolerance {
				t.Errorf("Calculate() = %v, want approximately %v", got, tt.expected)
			}
		})
	}
}

func TestCalculator_IsValid(t *testing.T) {
	tests := []struct {
		name   string
		data   string
		minEnt float64
		want   bool
	}{
		{
			name:   "github token above threshold",
			data:   "ghp_FAKE0TOKEN0FOR0TESTING0PURPOSES0ONLY",
			minEnt: 3.0,
			want:   true,
		},
		{
			name:   "example word below threshold",
			data:   "example_key_value",
			minEnt: 3.5,
			want:   false,
		},
		{
			name:   "aws access key meets threshold",
			data:   "AKIAFAKEKEYS4TESTING",
			minEnt: 2.5,
			want:   true,
		},
		{
			name:   "lowercase only below threshold",
			data:   "abcdef123456789",
			minEnt: 4.0,
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := New(tt.minEnt)
			if got := c.IsValid(tt.data); got != tt.want {
				t.Errorf("IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_isHexString(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{
			name: "valid hex",
			s:    "0123456789abcdefABCDEF",
			want: true,
		},
		{
			name: "not hex - letters",
			s:    "GHJKLASD",
			want: false,
		},
		{
			name: "not hex - symbols",
			s:    "0123456789abcdef!@#",
			want: false,
		},
		{
			name: "empty",
			s:    "",
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isHexString(tt.s); got != tt.want {
				t.Errorf("isHexString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_isSequentialOrRepeated(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{
			name: "sequential digits",
			s:    "1234567890123456",
			want: true,
		},
		{
			name: "all same characters",
			s:    "aaaaaaaaaaaaaa",
			want: true,
		},
		{
			name: "random string",
			s:    "wJalrXUtnFEMI",
			want: false,
		},
		{
			name: "sequential hex",
			s:    "0123456789abcdef",
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isSequentialOrRepeated(tt.s); got != tt.want {
				t.Errorf("isSequentialOrRepeated() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCalculateWithPenalty(t *testing.T) {
	tests := []struct {
		name      string
		data      string
		penalties []string
	}{
		{
			name:      "no penalties",
			data:      "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			penalties: []string{},
		},
		{
			name:      "hex penalty",
			data:      "0123456789abcdef0123456789abcdef",
			penalties: []string{"hex"},
		},
		{
			name:      "lowercase penalty",
			data:      "abcdefghijklmnopqrstuvwxyz",
			penalties: []string{"lowercase"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CalculateWithPenalty(tt.data, tt.penalties)
			base := New(0).Calculate(tt.data)

			if len(tt.penalties) > 0 && result >= base {
				t.Errorf("CalculateWithPenalty() with penalties should return lower value than base")
			}
		})
	}
}

func BenchmarkCalculate(b *testing.B) {
	c := New(3.5)
	data := "ghp_FAKE0TOKEN0FOR0TESTING0PURPOSES0ONLY"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Calculate(data)
	}
}

func BenchmarkCalculateLong(b *testing.B) {
	c := New(3.5)
	data := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEYwJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Calculate(data)
	}
}