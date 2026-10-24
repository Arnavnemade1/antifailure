package mysql

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/antifailure/antifailure/engine/internal/masking"
	"github.com/antifailure/antifailure/engine/internal/secrets"
	"github.com/antifailure/antifailure/engine/pkg/provider"
)

func TestParseURL_ReadsWhatAManifestWrites(t *testing.T) {
	t.Parallel()
	s, err := parseURL(secrets.New("mysql://app:s3cret@db.internal:3307/shop"))
	require.NoError(t, err)
	require.Equal(t, "app", s.user)
	require.Equal(t, "s3cret", s.password)
	require.Equal(t, "db.internal:3307", s.addr)
	require.Equal(t, "shop", s.database)
	require.Equal(t, "preferred", s.tls)

	s, err = parseURL(secrets.New("mysql://app@db.internal/shop?tls=true"))
	require.NoError(t, err)
	require.Equal(t, "db.internal:3306", s.addr, "a URL with no port means MySQL's own")
	require.Equal(t, "true", s.tls)
}

// A password is percent encoded in a URL. Handed to the driver as text it
// would end the user part of a DSN at its first @ or /.
func TestParseURL_APasswordWithURLSyntaxInItSurvivesTheRoundTrip(t *testing.T) {
	t.Parallel()
	s, err := parseURL(secrets.New("mysql://app:p%40ss%2Fw%3Ard@127.0.0.1:3306/shop"))
	require.NoError(t, err)
	require.Equal(t, "p@ss/w:rd", s.password)

	back, err := parseURL(s.in("af_env_abc").url())
	require.NoError(t, err)
	require.Equal(t, "p@ss/w:rd", back.password)
	require.Equal(t, "af_env_abc", back.database)
}

func TestParseURL_RefusesWhatIsNotAMySQLAddressWithoutQuotingIt(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{
		"postgres://u:hunter2@h/db",
		"http://u:hunter2@h:8123/db",
		"hunter2",
		"mysql://u:hunter2@h/a/b",
		"mysql://u:hunter2@h/db?tls=maybe",
	} {
		_, err := parseURL(secrets.New(bad))
		require.Error(t, err, bad)
		require.NotContains(t, err.Error(), "hunter2", "an error repeated the credential in %q", bad)
	}
}

func TestDatabaseOf(t *testing.T) {
	t.Parallel()
	require.Equal(t, "shop", DatabaseOf(secrets.New("mysql://u:p@h/shop")))
	require.Equal(t, "", DatabaseOf(secrets.New("mysql://u:p@h/")))
	require.Equal(t, "", DatabaseOf(secrets.New("not a url")))
}

// Masking derives every column's key from schema.table.column. A golden
// candidate is a new database each refresh, so the table is described under
// the source's name, and a foreign key into the candidate itself is renamed
// with it so the planner still sees both sides of the join.
func TestMaskingTable_IsNamedForTheSourceAndKeepsItsForeignKeys(t *testing.T) {
	t.Parallel()
	tbl := table{
		name: "orders",
		columns: []column{
			{name: "id", typ: "bigint", unique: true},
			{name: "customer_id", typ: "bigint", foreignKey: "af_cand_1.customers.id"},
			{name: "partner_id", typ: "bigint", foreignKey: "elsewhere.partners.id"},
			{name: "total_cents", typ: "bigint", generated: true},
		},
		primaryKey: []string{"id"},
	}
	mt := tbl.maskingTable("shop", "af_cand_1")
	require.Equal(t, "shop", mt.Schema)
	require.Equal(t, "mysql", mt.Engine)
	require.Equal(t, "shop.customers.id", mt.ColumnNamed("customer_id").ForeignKey)
	require.Equal(t, "elsewhere.partners.id", mt.ColumnNamed("partner_id").ForeignKey,
		"a foreign key into another database is that database's")
	require.True(t, mt.ColumnNamed("total_cents").Generated)
	require.Len(t, tbl.writableColumns(), 3, "a generated column is never written")
}

func TestRewritesKey(t *testing.T) {
	t.Parallel()
	tp := masking.TablePlan{
		OrderBy: []string{"id"},
		Columns: []masking.Assignment{{Column: masking.ColumnInfo{Name: "email"}}},
	}
	require.False(t, rewritesKey(tp))
	tp.Columns = append(tp.Columns, masking.Assignment{Column: masking.ColumnInfo{Name: "id"}})
	require.True(t, rewritesKey(tp))
}

func TestCapabilities_DeclareACopyRatherThanSharedStorage(t *testing.T) {
	t.Parallel()
	p, err := New(Options{ServerURL: secrets.New("mysql://root:x@127.0.0.1:1/")})
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })
	require.Equal(t, provider.DatastoreCaps{
		Engine: "mysql", Branching: true, Golden: true, CopyOnWrite: false,
	}, p.Capabilities())
	require.Equal(t, "mysql", p.Name())
}
