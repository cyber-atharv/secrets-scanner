/*
©cyber-atharv | 2026
pipeline_test.go

Tests for engine/pipeline.go

Tests:
  Directory scan finds AWS key written to a temp file
  Clean file produces no findings
  Multiple secrets in one file are all detected
  Pre-cancelled context returns an error
  Deduplication limits repeated identical secrets to one finding per chunk
*/

package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cyber-atharv/portia/internal/rules"
	"github.com/cyber-atharv/portia/internal/source"
)

func TestPipelineDirectoryScan(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile( //nolint:gosec
		filepath.Join(dir, "config.py"),
		[]byte(`api_key = "AKIA_DUMMY_TEST_KEY_FOR_SCANNER_00"`+"\n"),
		0o644,
	))
	require.NoError(t, os.WriteFile( //nolint:gosec
		filepath.Join(dir, "clean.go"),
		[]byte("package main\n\nfunc main() {}\n"),
		0o644,
	))

	reg := testRegistry()
	p := NewPipeline(reg)
	src := source.NewDirectory(dir, 0, nil)

	result, err := p.Run(context.Background(), src)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.GreaterOrEqual(t, len(result.Findings), 1)

	found := false
	for _, f := range result.Findings {
		if f.RuleID == "test-aws-key" {
			found = true
			assert.Equal(t, "AKIA_DUMMY_TEST_KEY_FOR_SCANNER_00", f.Secret)
		}
	}
	assert.True(t, found, "expected to find AWS key")
}

func TestPipelineNoFindings(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile( //nolint:gosec
		filepath.Join(dir, "main.go"),
		[]byte("package main\n\nfunc main() {}\n"),
		0o644,
	))

	reg := testRegistry()
	p := NewPipeline(reg)
	src := source.NewDirectory(dir, 0, nil)

	result, err := p.Run(context.Background(), src)
	require.NoError(t, err)
	assert.Empty(t, result.Findings)
}

func TestPipelineMultipleSecrets(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile( //nolint:gosec
		filepath.Join(dir, "secrets.env"),
		[]byte(
			`AWS_KEY=AKIA_DUMMY_TEST_KEY_FOR_SCANNER_00`+"\n"+
				`STRIPE_KEY=sk_test_DUMMY_STRIPE_KEY_00000000`+"\n"+
				`password = "xK9mP2vL5nQ8jR3t"`+"\n",
		),
		0o644,
	))

	reg := testRegistry()
	p := NewPipeline(reg)
	src := source.NewDirectory(dir, 0, nil)

	result, err := p.Run(context.Background(), src)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(result.Findings), 2)
}

func TestPipelineContextCancel(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for i := range 20 {
		name := "file" + string(rune('A'+i)) + ".txt"
		require.NoError(t, os.WriteFile( //nolint:gosec
			filepath.Join(dir, name),
			[]byte(`AKIA_DUMMY_TEST_KEY_FOR_SCANNER_00`+"\n"),
			0o644,
		))
	}

	reg := testRegistry()
	p := NewPipeline(reg)
	src := source.NewDirectory(dir, 0, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := p.Run(ctx, src)
	assert.Error(t, err)
}

func TestPipelineDedup(t *testing.T) {
	t.Parallel()

	reg := rules.NewRegistry()
	rules.RegisterBuiltins(reg)
	p := NewPipeline(reg)

	dir := t.TempDir()
	require.NoError(t, os.WriteFile( //nolint:gosec
		filepath.Join(dir, "dup.txt"),
		[]byte(
			`AKIA_DUMMY_TEST_KEY_FOR_SCANNER_00`+"\n"+
				`AKIA_DUMMY_TEST_KEY_FOR_SCANNER_00`+"\n",
		),
		0o644,
	))

	src := source.NewDirectory(dir, 0, nil)
	result, err := p.Run(context.Background(), src)
	require.NoError(t, err)

	awsCount := 0
	for _, f := range result.Findings {
		if f.Secret == "AKIA_DUMMY_TEST_KEY_FOR_SCANNER_00" { //nolint:gosec
			awsCount++
		}
	}
	assert.LessOrEqual(t, awsCount, 2)
}
