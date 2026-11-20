package main

import "testing"

// Sealed by the API's devicesecrets.seal with the same key: both sides must
// agree on the format.
const pythonSealed = "v1:fEJ85wa5pd_Doe01s3faoX_OtdekZa698C9JM_7bYjZDqNpyT7NUtjKSS23F8P0bOz82eEmWl5GdSO5vsJQdhLZ99Yg"

func TestOpenSealedReadsWhatTheAPIWrote(t *testing.T) {
	var got map[string]string
	if err := openSealed("test-credentials-key-0123456789abcdef", pythonSealed, &got); err != nil {
		t.Fatal(err)
	}
	if got["community"] != "public" || got["username"] != "u" {
		t.Fatalf("%v", got)
	}
	if err := openSealed("another-key-another-key-another-key!", pythonSealed, &got); err == nil {
		t.Fatal("wrong key accepted")
	}
	for _, bad := range []string{"", "plain", "v1:", "v1:@@@", "v1:AAAA"} {
		if err := openSealed("k", bad, &got); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	if err := openSealed("", pythonSealed, &got); err == nil {
		t.Fatal("no key accepted")
	}
}
