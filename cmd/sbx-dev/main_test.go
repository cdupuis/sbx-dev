package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheckBindAcceptsLoopback(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:7391", "[::1]:7391", "localhost:7391", "127.0.0.1:0"} {
		require.NoError(t, checkBind(addr, false), "addr %s", addr)
	}
}

func TestCheckBindRejectsNonLoopback(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:7391", "192.168.1.10:7391", "[::]:7391"} {
		require.Error(t, checkBind(addr, false), "addr %s must be refused without --allow-any-bind", addr)
	}
}

func TestCheckBindRejectsMissingHost(t *testing.T) {
	require.ErrorContains(t, checkBind(":7391", false), "explicit host")
}

func TestCheckBindHonoursOverride(t *testing.T) {
	require.NoError(t, checkBind("0.0.0.0:7391", true))
}

func TestStringListSplitsOnComma(t *testing.T) {
	var l stringList
	require.NoError(t, l.Set("create, exec ,,ls"))
	require.Equal(t, stringList{"create", "exec", "ls"}, l)
	require.NoError(t, l.Set("ps"))
	require.Equal(t, stringList{"create", "exec", "ls", "ps"}, l)
}
