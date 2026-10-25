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

// Masking knows a candidate's tables by the source's name and the scan reads
// them under the candidate's. What masking reports as copied unchanged is what
// the scan matches against, so it is named the scan's way: under the source's
// name it matched nothing and every unruled column counted as ruled.
func TestUnruledNames_AreTheDatabaseTheScanReads(t *testing.T) {
	t.Parallel()
	tbl := table{
		name: "vault",
		columns: []column{
			{name: "id", typ: "int", unique: true},
			{name: "signing_key", typ: "varbinary(32)"},
		},
		primaryKey: []string{"id"},
	}
	tables := []masking.Table{tbl.maskingTable("shop", "af_cand_1")}
	rules, err := masking.NewRuleSet(nil)
	require.NoError(t, err)
	plan := masking.BuildPlan(tables, rules.Assign(tables), "h")
	require.Contains(t, plan.CopiedUnchangedNames(), "shop.vault.signing_key",
		"precondition: the plan names the column by the source, which the scan never sees")
	require.Equal(t, []string{"af_cand_1.vault.signing_key"}, unruledNames(plan, "af_cand_1"))
}

// The scan refuses an unruled name it could never match rather than letting
// it fall through as a ruled column.
func TestUnruledUnder_RefusesANameUnderAnotherDatabase(t *testing.T) {
	t.Parallel()
	require.NoError(t, unruledUnder("af_cand_1", nil))
	require.NoError(t, unruledUnder("af_cand_1", []string{"af_cand_1.vault.signing_key"}))
	for _, bad := range []string{
		"shop.vault.signing_key",
		"af_cand_10.vault.signing_key",
		"af_cand_1.signing_key",
	} {
		err := unruledUnder("af_cand_1", []string{"af_cand_1.vault.id", bad})
		require.ErrorContains(t, err, bad)
	}
}

// A source in a form this does not read is refused, not taken for no source:
// taken for none, a real production produced an empty golden that verified
// clean. No address, and the conformance suite's placeholder, are none.
func TestOpenSource_RefusesAnAddressItCannotReadWithoutQuotingIt(t *testing.T) {
	t.Parallel()
	p := &Provider{}
	for _, none := range []string{"", "  ", "antifailure://conformance/source"} {
		src, err := p.openSource(secrets.New(none))
		require.NoError(t, err, none)
		require.Nil(t, src, none)
	}
	for _, bad := range []string{
		"mariadb://u:hunter2@db.internal:3306/shop",
		"jdbc:mysql://db.internal:3306/shop?password=hunter2",
		"u:hunter2@tcp(db.internal:3306)/shop",
		"postgres://u:hunter2@db.internal/shop",
	} {
		src, err := p.openSource(secrets.New(bad))
		require.Nil(t, src, bad)
		require.ErrorContains(t, err, "not a mysql:// URL", bad)
		require.NotContains(t, err.Error(), "hunter2", "an error repeated the credential in %q", bad)
	}
	_, err := p.openSource(secrets.New("mysql://u:hunter2@db.internal:3306/"))
	require.ErrorContains(t, err, "names no database")
}
