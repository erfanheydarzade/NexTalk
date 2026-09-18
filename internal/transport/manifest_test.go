package transport

import "testing"

func TestManifestValid(t *testing.T) {
	raw := []byte(`{"id":"filerelay","name":"FileRelay","version":"1.0.0","api_version":"1","entry":"filerelay-bridge","capabilities":["message","binary-transfer"],"permissions":["network","storage"]}`)
	m, err := ParseManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !m.HasCapability("message") || m.HasCapability("p2p") {
		t.Fatal("capability mismatch")
	}
}

func TestManifestInvalid(t *testing.T) {
	cases := []string{
		`{}`,
		`{"id":"BAD ID","name":"x","version":"1","api_version":"1","entry":"bin","capabilities":["message"]}`,
		`{"id":"x","name":"x","version":"1","api_version":"2","entry":"bin","capabilities":["message"]}`,
		`{"id":"x","name":"x","version":"1","api_version":"1","entry":"../evil","capabilities":["message"]}`,
		`{"id":"x","name":"x","version":"1","api_version":"1","entry":"bin","capabilities":[]}`,
		`{"id":"x","name":"x","version":"1","api_version":"1","entry":"bin","capabilities":["teleport"]}`,
		`{"id":"x","name":"x","version":"1","api_version":"1","entry":"bin","capabilities":["message"],"permissions":["identity-keys"]}`,
		`not json`,
	}
	for i, c := range cases {
		if _, err := ParseManifest([]byte(c)); err == nil {
			t.Fatalf("case %d must fail", i)
		}
	}
}
