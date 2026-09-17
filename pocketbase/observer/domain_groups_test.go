package observer

import "testing"

func TestRegisteredActivityDomain(t *testing.T) {
	for hostname, want := range map[string]string{
		" API.ChatGPT.COM. ":       "chatgpt.com",
		"a.b.example.co.uk":        "example.co.uk",
		"api.bücher.de":            "xn--bcher-kva.de",
		"one.github.io":            "one.github.io",
		"two.github.io":            "two.github.io",
		"notfacebook.com":          "notfacebook.com",
		"facebook.com.example.org": "example.org",
		"":                         "", "localhost": "", "192.0.2.1": "", "::1": "",
		"co.uk": "", "bad..com": "", "https://example.com": "",
		"*.example.com": "", "-bad.example.com": "",
	} {
		t.Run(hostname, func(t *testing.T) {
			if got := registeredActivityDomain(hostname); got != want {
				t.Errorf("got %q, want %q", got, want)
			}
		})
	}
}

func TestActivityDomainAliasValidation(t *testing.T) {
	for _, input := range []string{
		`null`, `[]`, `{`, `{"fbcdn.net":""}`,
		`{"*.fbcdn.net":"facebook.com"}`, `{"fbcdn.net":"FACEBOOK.COM"}`,
		`{"fbcdn.net":"facebook.com", "facebook.com":"meta.com"}`,
		`{"fbcdn.net":"facebook.com", "facebook.com":"fbcdn.net"}`,
		`{"facebook.com":"facebook.com"}`, `{"co.uk":"facebook.com"}`,
	} {
		if _, err := parseActivityDomainAliases([]byte(input)); err == nil {
			t.Errorf("accepted invalid mapping %s", input)
		}
	}
	for _, input := range []string{`{}`, `{"fbcdn.net":"facebook.com"}`, `{"cdn.fbcdn.net":"facebook.com"}`, string(activityDomainAliasesJSON)} {
		if _, err := parseActivityDomainAliases([]byte(input)); err != nil {
			t.Errorf("rejected valid mapping: %v", err)
		}
	}
}
