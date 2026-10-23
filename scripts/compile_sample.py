import subprocess
import tempfile
import os
import shutil

src_code = """package main

import (
	"fmt"
	"net/http"
	"os"
)

func main() {
	endpoint := "https://api.wallpaper-daemon.internal/v1/assets"
	configFile := "settings.json"
	fmt.Printf("Service starting with endpoint %s and config %s\\n", endpoint, configFile)
	if len(os.Args) > 1 && os.Args[1] == "--health" {
		fmt.Println("Status: Healthy")
		return
	}
	_ = http.ListenAndServe(":8080", nil)
}
"""

d = tempfile.mkdtemp(prefix="src_daemon_")
try:
    with open(os.path.join(d, "go.mod"), "w") as f:
        f.write("module servicedaemon\n\ngo 1.22\n")

    with open(os.path.join(d, "main.go"), "w") as f:
        f.write(src_code)

    target = r"C:\AI\jarvis-re-workbench\workspace\samples\service_daemon.exe"
    os.makedirs(os.path.dirname(target), exist_ok=True)
    res = subprocess.run(["go", "build", "-o", target, "."], cwd=d, capture_output=True, text=True)
    print("Go build RC:", res.returncode)
    if res.stderr:
        print("Go build error:", res.stderr)
    if os.path.isfile(target):
        print("Generated authentic binary size:", os.path.getsize(target), "bytes")
finally:
    shutil.rmtree(d, ignore_errors=True)
