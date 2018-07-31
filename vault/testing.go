package vault

import (
        "bufio"
        "os"
        "strconv"
        "strings"
        "testing"
)

var VaultDevPortString string

var VaultDevServerLogfile string

type VaultTestServerInfo struct {
        Address string
        Token   string
}

func NewVaultTestServerInfo(t *testing.T) *VaultTestServerInfo {
        if _, err := strconv.Atoi(VaultDevPortString); err != nil {
                t.Fatalf("Vault listener port must be an integer")
        }
        token := parseLogfile(t)
        return &VaultTestServerInfo{
                Address: "http://127.0.0.1:" + VaultDevPortString,
                Token:   token,
        }
}

// parseLogFile reads VaultDevServerLogfile line-by-line
// until it finds the root token, at which point it returns
// the root token. It will cause the test to fail if it
// does not find the root token
func parseLogfile(t *testing.T) string {
        var (
                target   = "Root Token: "
                uuid_len = 36
        )

        file, err := os.Open(VaultDevServerLogfile)
        if err != nil {
                t.Fatal("error opening Vault dev server log file: %v", err)
        }

        scanner := bufio.NewScanner(file)
        for scanner.Scan() {
                var (
                        line = scanner.Text()
                        idx = strings.Index(line, target)
                )
                
                if idx != -1 {
                        return line[idx + len(target):idx + len(target) + uuid_len]
                }
        }
        if err = scanner.Err(); err != nil {
                t.Fatalf("error reading Vault dev server log file: %v", err)
        }
        t.Fatal("root token not found in Vault dev server log file %s", VaultDevServerLogfile)
        return ""

}