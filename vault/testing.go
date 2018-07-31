package vault

import (
        "strconv"
        "testing"
)

var VaultDevPortString string

var VaultDevRootToken string

type VaultTestServerInfo struct {
        Address string
        Token   string
}

func NewVaultTestServerInfo(t *testing.T) *VaultTestServerInfo {
        if _, err := strconv.Atoi(VaultDevPortString); err != nil {
                t.Fatal("Vault listener port must be an integer")
        }
        if VaultDevRootToken == "" {
                t.Fatal("No Vault root token provided")
        }
        return &VaultTestServerInfo{
                Address: "http://127.0.0.1:" + VaultDevPortString,
                Token:   VaultDevRootToken,
        }
}
