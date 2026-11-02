package logs

import "testing"

const sampleEvents = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Service Control Manager' Guid='{555908d1}'/><EventID Qualifiers='16384'>7036</EventID><Level>4</Level><TimeCreated SystemTime='2026-11-02T03:30:01.1234567Z'/><EventRecordID>101</EventRecordID><Channel>System</Channel></System><EventData><Data Name='param1'>Windows Update</Data></EventData><RenderingInfo Culture='en-US'><Message>The Windows Update service
 entered the running state.</Message><Level>Information</Level></RenderingInfo></Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='disk'/><EventID>7</EventID><Level>2</Level><TimeCreated SystemTime='2026-11-02T03:31:00Z'/><EventRecordID>102</EventRecordID></System><EventData><Data>\Device\Harddisk0\DR0</Data></EventData></Event>`

func TestParseEvents(t *testing.T) {
	ev := parseEvents([]byte(sampleEvents))
	if len(ev) != 2 {
		t.Fatalf("got %d events", len(ev))
	}
	if ev[0].System.EventRecordID != 101 || ev[0].System.Provider.Name != "Service Control Manager" || ev[0].System.EventID != "7036" {
		t.Fatalf("first: %+v", ev[0].System)
	}
	if ev[1].RenderingInfo.Message != "" || ev[1].EventData.Data[0] != `\Device\Harddisk0\DR0` {
		t.Fatalf("second: %+v", ev[1])
	}
	if eventLevel(ev[1].System.Level, "") != "error" || eventLevel("4", "") != "info" {
		t.Fatal("levels")
	}
}
