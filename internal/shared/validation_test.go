// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2026 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the GNU Affero General Public License, Version 3 (AGPL-3.0)
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	https://www.gnu.org/licenses/agpl-3.0.en.html
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package shared

import (
	"net"
	"testing"
)

func TestIsReservedIP(t *testing.T) {
	reserved := []string{
		"127.0.0.1", "10.0.0.1", "192.168.1.5", "172.16.0.1",
		"169.254.1.1", "224.0.0.1", "0.0.0.0",
		"::1", "fe80::1", "::", "fc00::1",
	}
	for _, s := range reserved {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("test IP %q did not parse", s)
		}
		if !IsReservedIP(ip) {
			t.Errorf("IsReservedIP(%s) should be true", s)
		}
	}
	public := []string{"8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"}
	for _, s := range public {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("test IP %q did not parse", s)
		}
		if IsReservedIP(ip) {
			t.Errorf("IsReservedIP(%s) should be false", s)
		}
	}
}

// Gate between user input and fail2ban-client arguments.
func TestValidateIP(t *testing.T) {
	valid := []string{
		"1.2.3.4",
		"203.0.113.77",
		"255.255.255.255",
		"::1",
		"2001:db8::1",
		"10.0.0.0/8",
		"2001:db8::/32",
	}
	for _, ip := range valid {
		t.Run("valid/"+ip, func(t *testing.T) {
			if err := ValidateIP(ip); err != nil {
				t.Fatalf("ValidateIP(%q) = %v, want nil", ip, err)
			}
		})
	}

	invalid := []string{
		"",
		"   ",
		"not-an-ip",
		"1.2.3",
		"1.2.3.256",
		"1.2.3.4;rm -rf /",
		"1.2.3.4 && curl evil",
		"$(whoami)",
		"10.0.0.0/33",
		"../../etc/passwd",
	}
	for _, ip := range invalid {
		t.Run("invalid/"+ip, func(t *testing.T) {
			if err := ValidateIP(ip); err == nil {
				t.Fatalf("ValidateIP(%q) = nil, want an error", ip)
			}
		})
	}
}

func TestSplitCommaList(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"only whitespace", "   ", nil},
		{"only separators", ",,,", nil},
		{"single", "a", []string{"a"}},
		{"trims entries", " a , b ,c ", []string{"a", "b", "c"}},
		{"drops empty entries", "a,,b,", []string{"a", "b"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SplitCommaList(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("SplitCommaList(%q) = %#v, want %#v", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("SplitCommaList(%q) = %#v, want %#v", tc.in, got, tc.want)
				}
			}
		})
	}
}
