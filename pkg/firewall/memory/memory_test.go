package memory

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFirewallRecordsBans(t *testing.T) {
	fw := New()

	fw.BanIP("1.2.3.4", 10)
	fw.BanIP("5.6.7.8", 20)

	bans := fw.Bans()
	require.Len(t, bans, 2)
	require.Equal(t, "1.2.3.4", bans[0].IP)
	require.Equal(t, 10, bans[0].TimeoutInMinute)
	require.Equal(t, "5.6.7.8", bans[1].IP)
	require.Equal(t, 20, bans[1].TimeoutInMinute)
	require.Equal(t, 2, fw.BanCount())

	fw.Reset()
	require.Empty(t, fw.Bans())
	require.Equal(t, 0, fw.BanCount())
}
